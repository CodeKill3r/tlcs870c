/*
 *      TLCS870/c processor module for IDA.
 *      Copyright (c) 2016 Máté Sebõk < smfinc.org{at}gmail.com >
 *      Freeware.
 */

#include "tosh.hpp"

// calc realtive address
ea_t map_addr(ea_t base, int16 offs, char cmdsiz)
{
    int16 taddr;    //temp addr for 16bit calc
    taddr=base+cmdsiz;
    taddr+=offs;
    return (ea_t) taddr;
}

//--------------------
// function to fill the basic ALU functions
inline void cmdFillAlu(uchar aidx, optype_t op1t, uint16 op1val, optype_t op2t, uint16 op2val, char dtype)
{
  static const uchar alu[8]=
  {
    T870C_addc, T870C_add,  T870C_subb, T870C_sub,
    T870C_and, T870C_xor,  T870C_or, T870C_cmp};

  cmd.itype = alu[aidx];
  cmd.Op1.type = op1t;
  if (op1t == o_reg)
    cmd.Op1.reg = op1val;
  
  cmd.Op2.type = op2t;
  if (op2t == o_reg)
    cmd.Op2.reg = op2val;
  if (op2t == o_imm)
  {
    cmd.Op2.value = op2val;
    cmd.Op2.dtyp = dtype;
  }
}
//*****2byte reg prefix
int decodeRegPrefix(uchar regIdx)   //ret 0 = OK   1=Err
{
    uchar code = ua_next_byte();    //next byte
    if (code <= 0x3F)
    {
        //<alu> r,g
        cmdFillAlu((code&0x07), o_reg, rA+((code&0x38)>>3), o_reg, rA+regIdx, 0);
        return 0;
    };
    if ((code >= 0x60) && (code <= 0x67))
    {
        //<alu> g,n
        cmdFillAlu((code&0x07), o_reg, rA+regIdx, o_imm, ua_next_byte(), dt_byte);
        return 0;
    }
    if ((code >= 0x68) && (code <= 0x6F))
    {
        //<alu> gg,mn
        uint16 tval = ua_next_byte();
        tval += (ua_next_byte()<<8);        
        cmdFillAlu((code&0x07), o_reg, rWA+regIdx, o_imm, tval, dt_word);
        return 0;
    }
    if ((code >= 0x80) && (code <= 0xB7))
    {
        //<alu> rr,gg
        cmdFillAlu((code&0x07), o_reg, rWA+((code&0x38)>>3), o_reg, rWA+regIdx, 0);
        return 0;
    };
    if ((code >= 0xB8) && (code <= 0xBF))
    {
        //<alu> HL,gg
        cmdFillAlu((code&0x07), o_reg, rHL, o_reg, rWA+regIdx, 0);
        return 0;
    };
    switch(code)
    {
        case 0x40:
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:
            //LD r,g
            cmd.itype = T870C_ld;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = (code & 0x07)+ rA;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = regIdx + rA;
            break;
        case 0x48:
        case 0x49:
        case 0x4A:
        case 0x4B:
        case 0x4C:
        case 0x4D:
        case 0x4E:
            //LD rr,gg
            cmd.itype = T870C_ld;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = (code & 0x07)+ rWA;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = regIdx + rWA;
            break;
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
            //XOR CF,g.b
            cmd.itype = T870C_xor;
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fFlCF;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = regIdx + rA;
            cmd.Op2.bit = (code & 0x07) + b0;
            break;
        case 0x58:
        case 0x59:
        case 0x5A:
        case 0x5B:
        case 0x5C:
        case 0x5D:
        case 0x5E:
        case 0x5F:
            //LD CF,g.b
            cmd.itype = T870C_ld;
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fFlCF;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = regIdx + rA;
            cmd.Op2.bit = (code & 0x07) + b0;
            break;
        case 0x70:
        case 0x71:
        case 0x72:
        case 0x73:
        case 0x74:
        case 0x75:
        case 0x76:
        case 0x77:
            //XCH r,g
            cmd.itype = T870C_xch;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = (code & 0x07)+ rA;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = regIdx + rA;
            break;
        case 0x78:
        case 0x79:
        case 0x7A:
        case 0x7B:
        case 0x7C:
        case 0x7D:
        case 0x7E:
            //XCH rr,gg
            cmd.itype = T870C_xch;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = (code & 0x07)+ rWA;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = regIdx + rWA;
            break;
        case 0xC0:
        case 0xC1:
        case 0xC2:
        case 0xC3:
        case 0xC4:
        case 0xC5:
        case 0xC6:
        case 0xC7:
            //SET g.b
            cmd.itype = T870C_set;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            cmd.Op1.bit = (code & 0x07) + b0;
            break;
        case 0xC8:
        case 0xC9:
        case 0xCA:
        case 0xCB:
        case 0xCC:
        case 0xCD:
        case 0xCE:
        case 0xCF:
            //CLR g.b
            cmd.itype = T870C_clr;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            cmd.Op1.bit = (code & 0x07) + b0;
            break;
        case 0xD0:
        case 0xD1:
        case 0xD2:
        case 0xD3:
        case 0xD4:
        case 0xD5:
        case 0xD6:
        case 0xD7:            
            //JR cc,a
            cmd.itype = T870C_jr_cond;
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fCnM+(code&0x07);
            cmd.Op2.type = o_near;
            cmd.Op2.addr = ua_next_byte();
            cmd.Op2.addr |= ((code & 0x80)?0xFF00:0);
			cmd.Op2.addr = map_addr(cmd.ea,cmd.Op2.addr,3);
			cmd.Op2.dtyp = dt_code;
            break;
        case 0xD8:
            //PUSH gg
            cmd.itype = T870C_push;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rWA;
            break;
        case 0xD9:
            //POP gg
            cmd.itype = T870C_pop;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rWA;
            break;
        case 0xDA:
            //DAA g
            cmd.itype = T870C_daa;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            break;
        case 0xDB:
            //DAS g
            cmd.itype = T870C_das;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            break;
        case 0xDC:
            //PUSH PSW
            //if (regIdx)
            //    return 1;
            cmd.itype = T870C_push;
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fPSW;
            break;
        case 0xDD:
            //POP PSW
            //if (regIdx)
            //    return 1;
            cmd.itype = T870C_pop;
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fPSW;
            break;
        case 0xDE:
            //LD PSW,n
            //if (regIdx)
            //    return 1;
            cmd.itype = T870C_ld;
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fPSW;
            cmd.Op2.type = o_imm;
            cmd.Op2.value = ua_next_byte();
            break;
        case 0xE0:
        case 0xE1:
        case 0xE2:
        case 0xE3:
        case 0xE4:
        case 0xE5:
        case 0xE6:
        case 0xE7:
            //CPL g.b
            cmd.itype = T870C_cpl;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            cmd.Op1.bit = (code & 0x07) + b0;
            break;
        case 0xE8:
        case 0xE9:
        case 0xEA:
        case 0xEB:
        case 0xEC:
        case 0xED:
        case 0xEE:
        case 0xEF:
            //LD g.b,CF
            cmd.itype = T870C_ld;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            cmd.Op1.bit = (code & 0x07) + b0;
            cmd.Op2.type = o_phrase;
            cmd.Op2.phrase = fFlCF;
            break;
        case 0xF0:
            //SHLCA gg
            cmd.itype = T870C_shlca;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rWA;
            break;
        case 0xF1:
            //SHRCA gg
            cmd.itype = T870C_shrca;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rWA;
            break;
        case 0xF2:
            //MUL ggH, ggL
            if (regIdx>3)
                return 1;
            cmd.itype = T870C_mul;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = (regIdx<<1)+1 + rA;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = (regIdx<<1) + rA;
            break;
        case 0xF3:
            //DIV gg, C
            if ((regIdx>3) || (regIdx == 1))
                return 1;
            cmd.itype = T870C_div;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rWA;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = rC;
            break;
        case 0xF4:
            //SHLC g
            cmd.itype = T870C_shlc;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            break;
        case 0xF5:
            //SHRC g
            cmd.itype = T870C_shrc;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            break;
        case 0xF6:
            //ROLC g
            cmd.itype = T870C_rolc;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            break;
        case 0xF7:
            //RORC g
            cmd.itype = T870C_rorc;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            break;
        case 0xFA:
            //NEG CS, gg
            cmd.itype = T870C_neg;
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fCnCS;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = regIdx + rWA;
            break;
        case 0xFB:
            //RETN
            if (regIdx)
                return 1;
            cmd.itype = T870C_retn;
            break;
        case 0xFD:
            //CALL gg
            cmd.itype = T870C_call;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rWA;
            break;
        case 0xFE:
            //JP gg
            cmd.itype = T870C_jp;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rWA;
            break;
        case 0xFF:
            //SWAP g
            cmd.itype = T870C_swap;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = regIdx + rA;
            break;

        default:
            return 1;
    }
    return 0;
}
//***********
static void cmdFillSrcAlu(uchar aidx, uint16 reg)
{
  static const uchar alu[8]=
  {
    T870C_addc, T870C_add,  T870C_subb, T870C_sub,
    T870C_and, T870C_xor,  T870C_or, T870C_cmp};

  cmd.itype = alu[aidx];
  cmd.Op1.type = o_reg;
  cmd.Op1.reg = reg;
}
//***********
static void cmdFillSrcImmAlu(uchar aidx, uint8 val)
{
  static const uchar alu[8]=
  {
    T870C_addc, T870C_add,  T870C_subb, T870C_sub,
    T870C_and, T870C_xor,  T870C_or, T870C_cmp};

  cmd.itype = alu[aidx];
  cmd.Op2.type = o_imm;
  cmd.Op2.value = val;
}
//-----------------------------------------------------------------------------
static void ClearOperand(op_t &op)
{
  op.dtyp=dt_byte;
  op.type=o_void;
  op.specflag1=0;
  op.specflag2=0;
  op.offb=0;
  op.offo=0;
  op.reg=0;
  op.value=0;
  op.addr=0;
  op.specval=0;
}

//******2byte (src) mem indexed
int srcPrefDec(uchar code)
{
    //uchar code = ua_next_byte();    //next byte
    if (code <= 0x3F)
    {
        //<alu> r,(src)
        cmdFillSrcAlu((code&0x07), ((code&0x38)>>3)+rA);
        return 0;
    };
    if ((code >= 0x80) && (code <= 0xB7))
    {
        //<alu> rr,(src)
        cmdFillSrcAlu((code&0x07), ((code&0x38)>>3)+rWA);
        return 0;
    };
    if ((code >= 0xB8) && (code <= 0xBF))
    {
        //<alu> HL,(src)
        cmdFillSrcAlu((code&0x07), rHL);
        return 0;
    };
    if ((code >= 0x40) && (code <= 0x47))
    {
        //LD r,(src)
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code&0x07)+rA;
        return 0;
    };
    if ((code >= 0x48) && (code <= 0x4E))
    {
        //LD rr,(src)
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code&0x07)+rWA;
        return 0;
    };
    if ((code >= 0x70) && (code <= 0x77))
    {
        //XCH r,(src)
        cmd.itype = T870C_xch;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code&0x07)+rA;
        return 0;
    };
    if ((code >= 0xD8) && (code <= 0xDF))
    {
        //XCH rr,(src)
        cmd.itype = T870C_xch;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code&0x07)+rWA;
        if (code==0xDF)
            cmd.Op1.reg = rHL;
        return 0;
    };
    if (code == 0xF6)
    {
        //ROLD A,(src)
        cmd.itype = T870C_rold;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = rA;
        return 0;        
    }
    if (code == 0xF7)
    {
        //RORD A,(src)
        cmd.itype = T870C_rord;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = rA;
        return 0;        
    }
    if ((code >= 0x50) && (code <= 0x57))
    {
        //XOR CF,(src).b
        cmd.itype = T870C_xor;
        cmd.Op1.type = o_phrase;
        cmd.Op1.phrase = fFlCF;
        cmd.Op2.bit = (code & 0x07) + b0;
        return 0;
    };
    if ((code >= 0x58) && (code <= 0x5F))
    {
        //LD CF,(src).b
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_phrase;
        cmd.Op1.phrase = fFlCF;
        cmd.Op2.bit = (code & 0x07) + b0;
        return 0;
    };
    if (code == 0xFC)
    {
        //LD CF,(src).A
        cmd.itype = T870C_rord;
        cmd.Op1.type = o_phrase;
        cmd.Op1.phrase = fFlCF;
        cmd.Op2.bit = bA;
        return 0;        
    }

    //--exchange operands
    cmd.Op1.type = cmd.Op2.type;
    cmd.Op1.reg = cmd.Op2.reg;
    cmd.Op1.addr = cmd.Op2.addr;
    cmd.Op1.specval = cmd.Op2.specval;
    cmd.Op1.dtyp = cmd.Op2.dtyp;
    ClearOperand(cmd.Op2);
    
    if ((code >= 0x60) && (code <= 0x67))
    {
        //<alu> (src),n
        cmdFillSrcImmAlu((code&0x07),ua_next_byte() );
        return 0;
    };
    if ((code >= 0xC0) && (code <= 0xC7))    
    {
        //SET (src).b
        cmd.itype = T870C_set;
        cmd.Op1.bit = (code & 0x07) + b0;
        return 0;
    };
    if ((code >= 0xC8) && (code <= 0xCF))
    {
        //CLR (src).b
        cmd.itype = T870C_clr;
        cmd.Op1.bit = (code & 0x07) + b0;
        return 0;
    };
    if ((code >= 0xE0) && (code <= 0xE7))    
    {
        //CPL (src).b
        cmd.itype = T870C_cpl;
        cmd.Op1.bit = (code & 0x07) + b0;
        return 0;
    };
    if ((code >= 0xE8) && (code <= 0xEF))
    {
        //LD (src).b,CF
        cmd.itype = T870C_ld;
        cmd.Op1.bit = (code & 0x07) + b0;
        cmd.Op2.type = o_phrase;
        cmd.Op2.phrase = fFlCF;
        return 0;
    };
    switch(code)
    {
        case 0xF0:
            //INC (src)
            cmd.itype = T870C_inc;
            break;
        case 0xF2:
            //SET (src).A
            cmd.itype = T870C_set;
            cmd.Op1.bit = bA;
            break;
        case 0xF3:
            //LD (src).A,CF
            cmd.itype = T870C_ld;
            cmd.Op1.bit = bA;
            cmd.Op2.type = o_phrase;
            cmd.Op2.phrase = fFlCF;
            break;
        case 0xF8:
            //DEC (src)
            cmd.itype = T870C_dec;
            break;
        case 0xFA:
            //CLR (src).A
            cmd.itype = T870C_clr;
            cmd.Op1.bit = bA;
            break;
        case 0xFB:
            //CPL (src).A
            cmd.itype = T870C_cpl;
            cmd.Op1.bit = bA;
            break;
        case 0xFD:
            //CALL (src)
            cmd.itype = T870C_call;
            break;
        case 0xFE:
            //JP (src)
            cmd.itype = T870C_jp;
            break;
        default:
            return 1;
    }
    return 0;
}
//******2byte (dst) ld decode
int dstLdDec(uchar code)
{
    if ((code >= 0x68) && (code <= 0x6E))
    {
        cmd.Op2.type = o_reg;
        cmd.Op2.reg = (code & 0x07) + rWA;
        return 0;
    }
    if ((code >= 0x78) && (code <= 0x7F))
    {
        cmd.Op2.type = o_reg;
        cmd.Op2.reg = (code & 0x07) + rA;
        return 0;
    }
    if (code == 0xF9)
    {
        cmd.Op2.type = o_imm;
        cmd.Op2.value = ua_next_byte();
        return 0;
    }
    return 1;
}

//-----------------------------------------------------------------------------
// analyzer
int idaapi T870C_ana(void)
{
  ClearOperand(cmd.Op1);       // first operand - Dummy
  ClearOperand(cmd.Op2);       // second operand - Dummy
  ClearOperand(cmd.Op3);       // third operand - Dummy

  // get the first instruction byte
  uchar code = ua_next_byte();
  uchar addr_tmp;
  if ( (code & 0xF0) == 0x70)
  {
    //callv
    cmd.itype = T870C_callv;
    cmd.Op1.type = o_phrase;
    cmd.Op1.phrase = fVectAddr;
    cmd.Op1.addr = (code & 0x0F)<<1;
	cmd.Op1.addr = map_addr(0xFFB0, cmd.Op1.addr, 0);
	cmd.Op1.dtyp = dt_code;
    return cmd.size;
  }
  if (( (code & 0xF0) == 0x80) ||( (code & 0xF0) == 0x90))
  {
    //JRS T,addr
    cmd.itype = T870C_jrs;
    cmd.Op1.type = o_phrase;
    cmd.Op1.phrase = fCnT;
    cmd.Op2.type = o_near;
    cmd.Op2.addr = (code & 0x1F) | ((code & 0x10)?0xFFF0:0); //sign extending
	cmd.Op2.addr = map_addr(cmd.ea, cmd.Op2.addr, 2);
	cmd.Op2.dtyp = dt_code;
    return cmd.size;
  }
  if (( (code & 0xF0) == 0xA0) ||( (code & 0xF0) == 0xB0))
  {
    //JRS F,addr
    cmd.itype = T870C_jrs;
    cmd.Op1.type = o_phrase;
    cmd.Op1.phrase = fCnF;
    cmd.Op2.type = o_near;
    cmd.Op2.addr = (code & 0x1F) | ((code & 0x10)?0xFFF0:0);
	cmd.Op2.addr = map_addr(cmd.ea, cmd.Op2.addr, 2);
	cmd.Op2.dtyp = dt_code;
    return cmd.size;
  }
  
  switch(code)
  {
    //1 byte opcode
    ///no operands
    case 0x00:
        //NOP
        cmd.itype = T870C_nop;
        break;
    case 0xFA:
        //RET
        cmd.itype = T870C_ret;
        break; 
    case 0xFB:
        //RETI
        cmd.itype = T870C_reti;
        break;
    case 0xFF:
        //SWI
        cmd.itype = T870C_swi;
        break;
    ///include operamds
    case 0x04:
        //CLR CF
        cmd.itype = T870C_clr;
        cmd.Op1.type = o_phrase;
        cmd.Op1.phrase = fFlCF;
        break;
    case 0x05:
        //SET CF
        cmd.itype = T870C_set;
        cmd.Op1.type = o_phrase;
        cmd.Op1.phrase = fFlCF;        
        break;
    case 0x06:
        //CPL CF
        cmd.itype = T870C_cpl;
        cmd.Op1.type = o_phrase;
        cmd.Op1.phrase = fFlCF;
        break;
    case 0x0D:
        //LD A,(HL)
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = rA;
        cmd.Op2.type = o_ireg;
        cmd.Op2.reg = rHL;
        break;
    case 0x0F:
        //LD (HL),A
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_ireg;
        cmd.Op1.phrase = rHL;
        cmd.Op2.type = o_reg;
        cmd.Op2.reg = rA;
        break;
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
        //LD A,r
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = rA;
        cmd.Op2.type = o_reg;
        cmd.Op2.reg = (code & 0x07)+ rA;
        break;
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x24:
    case 0x25:
    case 0x26:
    case 0x27:
        //INC r
        cmd.itype = T870C_inc;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code & 0x07)+ rA;
        break;
    case 0x28:
    case 0x29:
    case 0x2A:
    case 0x2B:
    case 0x2C:
    case 0x2D:
    case 0x2E:
    case 0x2F:
        //DEF r
        cmd.itype = T870C_dec;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code & 0x07)+ rA;
        break;
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
        //INC rr
        cmd.itype = T870C_inc;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code & 0x07)+ rWA;
        break;
    case 0x38:
    case 0x39:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3D:
    case 0x3E:
        //DEC rr
        cmd.itype = T870C_dec;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code & 0x07)+ rWA;
        break;
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
        //LD r,A
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code & 0x07)+ rA;
        cmd.Op2.type = o_reg;
        cmd.Op2.reg = rA;
        break;        
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
        //PUSH rr
        cmd.itype = T870C_push;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code & 0x03)+ rWA;
        break;
    case 0xD0:
    case 0xD1:
    case 0xD2:
    case 0xD3:
        //POP rr
        cmd.itype = T870C_pop;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code & 0x03)+ rWA;
        break;
    ///complicated 1byte opcodes
    case 0x07:
        //CMP (x),n
        cmd.itype = T870C_cmp;
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op2.type = o_imm;
        cmd.Op2.value = ua_next_byte();
        break;
    case 0x08:
        //LDW (x),mn
        cmd.itype = T870C_ldw;
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op2.type = o_imm;
        cmd.Op2.value = ua_next_byte();
        cmd.Op2.value += (ua_next_byte()<<8);
        cmd.Op2.dtyp = dt_word;
        break;
    case 0x09:
        //LDW (HL),mn
        cmd.itype = T870C_ldw;
        cmd.Op1.type = o_ireg;
        cmd.Op1.reg = rHL;
        cmd.Op2.type = o_imm;
        cmd.Op2.value = ua_next_byte();
        cmd.Op2.value += (ua_next_byte()<<8);
        cmd.Op2.dtyp = dt_word;
        break;
    case 0x0A:
        //LD (x),n
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op2.type = o_imm;
        cmd.Op2.value = ua_next_byte();
        break;
    case 0x0B:
        //LD (HL),n
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_ireg;
        cmd.Op1.reg = rHL;
        cmd.Op2.type = o_imm;
        cmd.Op2.value = ua_next_byte();
        break;
    case 0x0C:
        //LD A,(x)
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = rA;
        cmd.Op2.type = o_mem;
        cmd.Op2.addr = ua_next_byte();
        break;
    case 0x0E:
        //LD (x),A
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op2.type = o_reg;
        cmd.Op2.reg = rA;
        break;
    case 0x18:
    case 0x19:
    case 0x1A:
    case 0x1B:
    case 0x1C:
    case 0x1D:
    case 0x1E:
    case 0x1F:
        //LD r,n
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code & 0x07)+ rA;
        cmd.Op2.type = o_imm;
        cmd.Op2.value = ua_next_byte();
        break;
    case 0x37:
        //LD SP,SP+d
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = rSP;
        cmd.Op2.type = o_stkimm;
        cmd.Op2.value = ua_next_byte();
        cmd.Op2.step = sInc;
        break;
    case 0x3F:
        //LD SP,SP-d
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = rSP;
        cmd.Op2.type = o_stkimm;
        cmd.Op2.value = ua_next_byte();
        cmd.Op2.step = sDec;
        break;
    case 0x48:
    case 0x49:
    case 0x4A:
    case 0x4B:
    case 0x4C:
    case 0x4D:
    case 0x4E:
        //LD rr,mn
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg = (code & 0x07)+ rWA;
        cmd.Op2.type = o_imm;
		cmd.Op2.value = ua_next_byte();
		cmd.Op2.value += (ua_next_byte()<<8);
        cmd.Op2.dtyp = dt_word;
        break;
    case 0x58:
    case 0x59:
    case 0x5A:
    case 0x5B:
    case 0x5C:
    case 0x5D:
    case 0x5E:
    case 0x5F:
        //LD CF,(x).b
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_phrase;
        cmd.Op1.phrase = fFlCF;
        cmd.Op2.type = o_mem;
        cmd.Op2.addr = ua_next_byte();
        cmd.Op2.bit = (code & 0x07) + b0;
        break;
    case 0x60:
        //ADDC A,n
    case 0x61:
        //ADD A,n
    case 0x62:
        //SUBB A,n
    case 0x63:
        //SUB A,n
    case 0x64:
        //AND A,n
    case 0x65:
        //XOR A,n
    case 0x66:
        //OR A,n
    case 0x67:
        //CMP A,n
        cmdFillAlu((code & 0x07), o_reg, rA,o_imm, ua_next_byte(), dt_byte);
        break;
    case 0xC0:
    case 0xC1:
    case 0xC2:
    case 0xC3:
    case 0xC4:
    case 0xC5:
    case 0xC6:
    case 0xC7:
        //SET (x).b
        cmd.itype = T870C_set;
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op1.bit = (code & 0x07) + b0;
        break;
    case 0xC8:
    case 0xC9:
    case 0xCA:
    case 0xCB:
    case 0xCC:
    case 0xCD:
    case 0xCE:
    case 0xCF:
        //CLR (x).b
        cmd.itype = T870C_clr;
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op1.bit = (code & 0x07) + b0;
        break;
    case 0xD8:
    case 0xD9:
    case 0xDA:
    case 0xDB:
    case 0xDC:
    case 0xDD:
    case 0xDE:
    case 0xDF:
        //JR cc,a
        cmd.itype = T870C_jr_cond;
        cmd.Op1.type = o_phrase;
        cmd.Op1.phrase = fCnEQ+(code&0x07);
        cmd.Op2.type = o_near;
		addr_tmp=ua_next_byte();
        cmd.Op2.addr = addr_tmp;
        cmd.Op2.addr |= ((addr_tmp & 0x80)?0xFF00:0);
		cmd.Op2.addr = map_addr(cmd.ea, cmd.Op2.addr, 2);
		cmd.Op2.dtyp = dt_code;
        break;
    case 0xF9:
        //LD RBS,0 or 1
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_phrase;
        cmd.Op1.phrase = fRBS;
        cmd.Op2.type = o_imm;
        cmd.Op2.value = ua_next_byte(); 
        if (cmd.Op2.value == 0x02)
            cmd.Op2.value=1;
        else if (cmd.Op2.value)
            return 0;   //not valid, only 0x00 of 0x02 are allowed here
        break;
    case 0xFC:    
        //JR a
        cmd.itype = T870C_jr;
        cmd.Op1.type = o_near;
		addr_tmp=ua_next_byte();
        cmd.Op1.addr = addr_tmp; 
        cmd.Op1.addr |= ((addr_tmp & 0x80)?0xFF00:0);
		cmd.Op1.addr = map_addr(cmd.ea, cmd.Op1.addr, 2);
		cmd.Op1.dtyp = dt_code;
        break;
    case 0xFD:
        //CALL mn
        cmd.itype = T870C_call;
        cmd.Op1.type = o_far;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op1.addr += (ua_next_byte()<<8);
        break;
    case 0xFE:
        //JP mn
        cmd.itype = T870C_jp;
        cmd.Op1.type = o_far;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op1.addr += (ua_next_byte()<<8);
        break;
//2byte opcodes--------------
    case 0xE8:
    case 0xE9:
    case 0xEA:
    case 0xEB:
    case 0xEC:
    case 0xED:
    case 0xEE:
    case 0xEF:
        //register prefix
        decodeRegPrefix(code & 0x07);
        break;


    case 0xD4:
    case 0xD5:
    case 0xD6:
        //(src) mem indexed
        cmd.Op2.type = o_displ;
        cmd.Op2.reg = (code & 3) + rIX;
        cmd.Op2.addr = ua_next_byte();
        srcPrefDec(ua_next_byte());
        break;
    case 0xD7:
        cmd.Op2.type = o_displ;
        cmd.Op2.reg = rHL;
        cmd.Op2.addr = ua_next_byte();
        srcPrefDec(ua_next_byte());
        break;
    case 0xE0:
        //(src) (x)
        cmd.Op2.type = o_mem;
        cmd.Op2.addr = ua_next_byte();
        srcPrefDec(ua_next_byte());
        break;    
    case 0xE1:
        //(src) (vw)
        cmd.Op2.type = o_mem;
        cmd.Op2.addr = ua_next_byte();
        cmd.Op2.addr += (ua_next_byte()<<8);
        cmd.Op2.dtyp = dt_word;
        srcPrefDec(ua_next_byte());
        break;
    case 0xE2:
    case 0xE3:
    case 0xE4:
    case 0xE5:
        //(src) mem prefix
        cmd.Op2.type = o_ireg;
        cmd.Op2.reg = (code - 0xE2) + rDE;
        srcPrefDec(ua_next_byte());
        break;
    case 0xE6:
        //(src) (+SP)
        cmd.Op2.type = o_stkstp;
        cmd.Op2.reg = rSP;
        cmd.Op2.step = sInc;
        srcPrefDec(ua_next_byte());
        break;
    case 0xE7:
        //(src) (HL+C)
        cmd.Op2.type = o_compireg;
        cmd.Op2.reg = rHL;
        cmd.Op2.secreg = rC;
        srcPrefDec(ua_next_byte());
        break;
    case 0x4F:
        //(src) (PC+A)
        cmd.Op2.type = o_compireg;
        cmd.Op2.reg = rPC;
        cmd.Op2.secreg = rA;
        srcPrefDec(ua_next_byte());
        break;


	case 0x54:
    case 0x55:
    case 0x56:
        //(dst) mem indexed
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_displ;
        cmd.Op1.reg = (code & 0x03) + rIX;
        cmd.Op1.addr = ua_next_byte();
        dstLdDec(ua_next_byte());
        break;
    case 0x57:
        //(dst) mem indexed
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_displ;
        cmd.Op1.reg = rHL;
        cmd.Op1.addr = ua_next_byte();
        dstLdDec(ua_next_byte());
        break;
    case 0xF0:
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = ua_next_byte();
        dstLdDec(ua_next_byte());
        break;
    case 0xF1:
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op1.addr += (ua_next_byte()<<8);
        cmd.Op1.dtyp = dt_word;
        dstLdDec(ua_next_byte());
        break;
    case 0xF2:
    case 0xF3:
    case 0xF4:
    case 0xF5:
        //(dst) mem prefix
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_ireg;
        cmd.Op1.reg = (code - 0xF2) + rDE;
        dstLdDec(ua_next_byte());
        break;
    case 0xF6:
        //(dst) (SP-)
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_stkstp;
        cmd.Op1.reg = rSP;
        cmd.Op1.step = sDec;
        dstLdDec(ua_next_byte());
        break;
    case 0xF7:
        //(dst) (HL+C)
        cmd.itype = T870C_ld;
        cmd.Op1.type = o_compireg;
        cmd.Op1.reg = rHL;
        cmd.Op1.secreg = rC;
        dstLdDec(ua_next_byte());
        break;

    default:
        return 0;
  };
  return cmd.size;
}
