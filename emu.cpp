/*
 *      TLCS870/c processor module for IDA.
 *      Copyright (c) 2016 Mate Sebok < smfinc.org{at}gmail.com >
 *      Freeware.
 */

#include "tosh.hpp"

static bool flow;       // stop check
//----------------------------------------------------------------------
// put to use / modify operand
static void TouchArg(op_t &x,int isAlt,int isload)
{
ea_t ea = toEA(codeSeg(x.addr,x.n), x.addr); //toEA(codeSeg(map_ea,x.n), map_ea);
switch ( x.type ) {
// this part is not used!
case o_void:  break;
//indirect
case o_ireg:
case o_compireg:
case o_stkstp:
case o_stkimm:
// there is also nothing to do
case o_reg:           break;
case o_phrase:                // 2 registers or indirect addressing
            if ( x.phrase==fVectAddr )
            {
                ua_add_cref(x.offb,ea,fl_CF);
                flow = func_does_return(ea);
            }
        break;
// it is also not analyze
case o_displ:         break;

// immediate operand
case o_imm:     // direct can not be changed
            if ( ! isload ) goto badTouch;
            // deliver immediate operand check
            doImmd(cmd.ea);
            // if not forced, and flagged offset
            if ( !isAlt && isOff(uFlag,x.n) )
                    // this offset !
                    ua_add_dref(x.offb,x.value,dr_O);
        break;

// jump or call to relative address
case o_near:    // it's a call ? (Or jump)
            if ( InstrIsSet(cmd.itype,CF_CALL) ){
                    // put a link to the code
                    ua_add_cref(x.offb,ea,fl_CN);
                    // a function without return ?
                    flow = func_does_return(ea);
            }
			else
			{
				ua_add_cref(x.offb,ea,fl_JN);
				//add_cref(cmd.ea,ea,fl_JN);
			}
        break;
// far jump/call to absolute address
case o_far:
            if ( InstrIsSet(cmd.itype,CF_CALL) ){
                    ua_add_cref(x.offb,ea,fl_CF);
					//add_cref(cmd.ea,ea,fl_CF);
                    flow = func_does_return(ea);
            }
            else
			{
				ua_add_cref(x.offb,ea,fl_JF);
				//add_cref(cmd.ea,ea, fl_JF);
			}

        break;
                
// reference memory
case o_mem:     
            // make the data to the specified address
            ua_dodata2(x.offb, ea, x.dtyp);
            // if you change - put variable
            if ( ! isload ) doVar(ea);
            // add a reference to the memory
            ua_add_dref(x.offb,ea,isload ? dr_R : dr_W);
        break;

// etc. - will report an error
default:
badTouch:
        warning("%a %s,%d: bad optype %d",
                        cmd.ea, cmd.get_canon_mnem(),
                        x.n, x.type);
        break;
}
}

//----------------------------------------------------------------------
// Emulate an instruction
// This function should:
//      - create all xrefs from the instruction
//      - perform any additional analysis of the instruction/program
//        and convert the instruction operands, create comments, etc.
//      - create stack variables
//      - analyze the delayed branches and similar constructs
// The kernel calls ana() before calling emu(), so you may be sure that
// the 'cmd' structure contains a valid and up-to-date information.
// You are not allowed to modify the 'cmd' structure.
// Upon entering this function, the 'uFlag' variable contains the flags of
// cmd.ea. If you change the characteristics of the current instruction, you
// are required to refresh 'uFlag'.
// Usually the kernel calls emu() with consecutive addresses in cmd.ea but
// you can't rely on this - for example, if the user asks to analyze an
// instruction at arbirary address, his request will be handled immediately,
// thus breaking the normal sequence of emulation.
// If you need to analyze the surroundings of the current instruction, you
// are allowed to save the contents of the 'cmd' structure and call ana().
// For example, this is a very common pattern:
//  {
//    insn_t saved = cmd;
//    if ( decode_prev_insn(cmd.ea) != BADADDR )
//    {
//      ....
//    }
//    cmd = saved;
//  }
//
// This sample emu() function is a very simple emulation engine.
int idaapi T870C_emu(void)
{
  uint32 Feature = cmd.get_canon_feature();
  // We obtain operands
  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);

  flow = ((Feature & CF_STOP) == 0);

  // mark the references of the two operands
  if ( Feature & CF_USE1) TouchArg(cmd.Op1, flag1, 1 );
  if ( Feature & CF_USE2) TouchArg(cmd.Op2, flag2, 1 );
  // We put in place a transition
  if ( Feature & CF_JUMP) QueueSet(Q_jumps,cmd.ea );

  // We deliver change
  if ( Feature & CF_CHG1) TouchArg(cmd.Op1, flag1, 0 );
  if ( Feature & CF_CHG2) TouchArg(cmd.Op2, flag2, 0 );
 
  // if the execution flow is not stopped here, then create
  // a xref to the next instruction.
  // Thus we plan to analyze the next instruction.

  if (flow) ua_add_cref(0,cmd.ea+cmd.size,fl_F );

  return(1);
}
