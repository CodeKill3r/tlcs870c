/*
 *      TLCS870/c processor module for IDA.
 *      Copyright (c) 2016 Mate Sebok < smfinc.org{at}gmail.com >
 *      Freeware.
 */

#include "tosh.hpp"

static const char *const phrases[] =
{
  // null
  "",
  // conditions
  "EQ", "NE", "LT", "GE", "LE", "GT" , "T", "F",
  "M", "P", "SLT", "SGE", "SLE", "SGT", "VS", "VC",
  "CS",
  "CF",
  // special register
  // 
  "PSW","RBS"
};


//----------------------------------------------------------------------
// generate the text representation of an operand
bool idaapi T870C_outop(op_t &x)
{
  ea_t v;
  char buf[MAXSTR];
  switch ( x.type )
  {
    // register and regbit type     R|RR[.b]
    case o_reg:
          if ((x.reg) && (x.reg<=rSP))
          {
            out_register(ph.regNames[x.reg]);
            if (x.bit)  //bit addressing
            {
              out_symbol('.');
              if (x.bit==bA)
              {
                out_symbol('?');
                msg("Bad bit type=%x\n",(int)x.bit);
              }
              else
                out_long(x.bit-1,10);
            }
          }
          else
          {
            out_symbol('?');
            msg("Bad reg Register Ref=%x\n",(int)x.reg);
          }
          break;
    // SP+/-d
    case o_stkimm:
        out_register(ph.regNames[rSP]);
        if (x.step==sInc)
            out_symbol('+');
        else
            out_symbol('-');
        OutValue(x, OOFS_NOSIGN|OOF_NUMBER|OOFW_8);
        break; 
    ///INDIRECT----
    // indirect register/bit addressing (RR)[.b]
    case o_ireg:
          out_symbol('(');
          if ((x.reg) && (x.reg<=rSP))
          {
            out_register(ph.regNames[x.reg]);
            //no bit addressing
          }
          else
          {
            out_symbol('?');
            msg("Bad ireg Register Ref=%x\n",(int)x.reg);
          }
          out_symbol(')');
          if (x.bit)  //bit addressing
          {
            out_symbol('.');
            if (x.bit==bA)
              out_register(ph.regNames[rA]);
            else
              out_long(x.bit-1,10);
          }
          break;
    // indirect displacement (reg + const)/bit  (RR+d)[.b]
    case o_displ:
          out_symbol('(');
          if ((x.reg) && (x.reg<=rSP))
          {
            out_register(ph.regNames[x.reg]);
            OutValue(x, OOF_ADDR|OOFS_NEEDSIGN|OOF_SIGNED|OOF_NUMBER|OOFW_8);
          }
          else
          {
            out_symbol('?');
            msg("Bad displ Register Ref=%x\n",(int)x.reg);
          }
          out_symbol(')');
          if (x.bit)  //bit addressing
          {
            out_symbol('.');
            if (x.bit==bA)
              out_register(ph.regNames[rA]);
            else
              out_long(x.bit-1,10);
          }
          break;
    // two register indirect (HL+C)[.b] | (PC+A)[.b]
    case o_compireg:
          out_symbol('(');
          if (x.reg==rHL)
          {
            out_register(ph.regNames[x.reg]);
            out_symbol('+');
            out_register(ph.regNames[x.secreg]);
          }
          else
          {
            out_register("PC");
            out_symbol('+');
            out_register(ph.regNames[x.secreg]);
          }
          out_symbol(')');
          if (x.bit)  //bit addressing
          {
            out_symbol('.');
            if (x.bit==bA)
              out_register(ph.regNames[rA]);
            else
              out_long(x.bit-1,10);
          }
          break;
    // stack increment/decrement   (+SP)[.b] | (SP-)
    case o_stkstp:
          out_symbol('(');
          if (x.reg==rSP)
          {
            if (x.step==sInc)
                out_symbol('+');
            out_register(ph.regNames[x.reg]);
            if (x.step==sDec)
                out_symbol('-');
          }
          else
          {
            out_symbol('?');
            msg("Bad stkstp Register Ref=%x\n",(int)x.reg);
          }
          out_symbol(')');
          if (x.bit)  //bit addressing
          {
            out_symbol('.');
            if (x.bit==bA)
              out_register(ph.regNames[rA]);
            else
              out_long(x.bit-1,10);
          }
          break;
    // indirect memory addressing (x)[.b] | (wv)[.b]
    case o_mem:
          out_symbol('(');
          OutValue(x, OOF_ADDR|OOFS_NOSIGN|OOFW_IMM);
          out_symbol(')');
          if (x.bit)  //bit addressing
          {
            out_symbol('.');
            if (x.bit==bA)
              out_register(ph.regNames[rA]);
            else
              out_long(x.bit-1,10);
          }
          break;    
    
    // immediate value
    case o_imm:
        OutValue(x, OOFS_NOSIGN|OOF_NUMBER|OOFW_IMM);
        break;
    // jump to fix address
    case o_far:
        OutValue(x, OOF_ADDR|OOFS_NOSIGN|OOFW_16);
        break;
    // special cases
    case o_phrase:
        if (x.phrase<fVectAddr)
        {
            OutLine(phrases[x.phrase]);
        }
        else    //vector addressing   (FFB0+x.addr)
        {
          out_symbol('(');          
          //x.addr+=0xffb0;
          //v=map_addr(0xFFB0, (int16) x.addr, 0);
          //out_addr_tag(v);
		  //x.addr=v;
		  //warning("callv out: %a: bad optype %a", cmd.ea, v);
          OutValue(x, OOF_ADDR|OOFS_NOSIGN|OOFW_16);
          out_symbol(')');        
        }
        break;    
    // realtive jump
    case o_near:
        //v=map_addr(cmd.ip, (int16) x.addr, x.opcode_add);
        //out_addr_tag(v);
		//warning("near addr out: %a: bad optype %a", cmd.ea, v);
		//if ( get_name_expr(cmd.ea+x.opcode_add, x.n, v, v, buf, sizeof(buf)) <= 0 )
		//x.addr=v;
		{
			// now print the offset
			//out_addr_tag(v);
            //out_name_expr(x,v,x.addr);
			OutValue(x, OOF_ADDR|OOFS_NOSIGN|OOFW_16);
			//QueueSet(Q_noName, cmd.ea);
		}
        break;
    case o_void:    // no operand
        return 0;
    default:        // default error
        warning("out: %a: bad optype %d", cmd.ea, x.type);
        break;
  }
  return 1;
}

//----------------------------------------------------------------------
// generate a text representation of an instruction
// the information about the instruction is in the 'cmd' structure 
void idaapi T870C_out(void)
{
  char buf[MAXSTR];
   init_output_buffer(buf, sizeof(buf)); // setup the output pointer

  // mnemonic
  OutMnem();

  // first operand
  if ( cmd.Op1.type!=o_void)out_one_operand(0 );

  // second operand
  if ( cmd.Op2.type != o_void ){
        out_symbol(',');
        OutChar(' ');
        out_one_operand(1);
  }

  // We derive immediate data, if they exist
  if ( isVoid(cmd.ea,uFlag,0) )
    OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) )
    OutImmChar(cmd.Op2);

  // EOL
  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
// Listing header text
void idaapi T870C_header(void)
{
  gen_header(GH_PRINT_ALL, device[0] ? device : NULL, deviceparams);
}

//--------------------------------------------------------------------------
// generate start of a segment
void idaapi T870C_segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  const char *SegType = Sarea->type==SEG_CODE ? "CSEG"
                      : Sarea->type==SEG_DATA ? "DSEG"
                      :                         "RSEG";
  // We derive a line like RSEG <NAME>
  char sn[MAXNAMELEN];
  get_segm_name(Sarea,sn,sizeof(sn));
  printf_line(-1,"%s %s ",SegType, sn);
  // if the offset is not zero - and derive (ORG XXXX)
  if ( inf.s_org )
  {
    ea_t org = ea - get_segm_base(Sarea);
    if( org != 0 )
    {
      char bufn[MAX_NUMBUF];
      btoa(bufn, sizeof(bufn), org);
      printf_line(-1, "%s %s", ash.origin, bufn);
    }
  }
}

//--------------------------------------------------------------------------
// generate end of the disassembly
void idaapi T870C_footer(void)
{
  //char buf[MAXSTR];
  //char *const end = buf + sizeof(buf);
  //if ( ash.end != NULL )
  //{
  //  MakeNull();
  //  char *ptr = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);
  //  qstring name;
  //  if ( get_colored_name(&name, inf.beginEA) > 0 )
  //  {
  //    size_t i = strlen(ash.end);
  //    do
  //      APPCHAR(ptr, end, ' ');
  //    while ( ++i < 8 );
  //    APPEND(ptr, end, name.begin());
  //  }
  //  MakeLine(buf, inf.indent);
  //}
  //else
  //{
  //  gen_cmt_line("end of file");
  //}
  char name[MAXSTR];
  get_colored_name(BADADDR, inf.beginEA, name, sizeof(name));
  const char *end = ash.end;
  if ( end == NULL )
    printf_line(inf.indent,COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    printf_line(inf.indent,COLSTR("%s",SCOLOR_ASMDIR)
                  " "
                  COLSTR("%s %s",SCOLOR_AUTOCMT), ash.end, ash.cmnt, name);
}

//--------------------------------------------------------------------------
void idaapi T870C_data(ea_t ea)
{
  gl_name = 1;
  intel_data(ea);
}
