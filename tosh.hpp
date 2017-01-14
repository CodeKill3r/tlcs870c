/*
 *      TLCS870/c processor module for IDA.
 *      Copyright (c) 2016 Mate Sebok < smfinc.org{at}gmail.com >
 *      Freeware.
 */

//#define NO_OBSOLETE_FUNCS

#ifndef _TOSH_HPP
#define _TOSH_HPP

//#include <ida.hpp>
//#include <idp.hpp>

#include <idaidp.hpp>
#include <diskio.hpp>
#include <cstdint>
#include "ins.hpp"

#define o_ireg      o_idpspec1      //register indirect memory (with or w/o spec displacement)
#define o_compireg  o_idpspec2      //composition of 2 register indirect (HL+C) (PC+A)
#define o_stkstp    o_idpspec3      //stack pre-inc / postt-dec
#define o_stkimm    o_idpspec4      //add to or sub from stack immediate

//used in jump and call addressing
#define rel_addr    specval_shorts.low      //only in fVectAddr
#define opcode_add  specval_shorts.high

//used in memory addressing
#define secreg      specval_shorts.low
#define bit         specval_shorts.high     //for bit-addressing

//stack pre-inc or post-dec
#define step        specval_shorts.low      //1=(+SP)  2=(SP-)

///addressing modes:
//--mem reg indirect
//reg_indirect          (HL),(DE),(IX),(IY)     o_ireg
//reg_indirect_displac  (HL+d),(IX+d),(IY+d)    o_disp
//reg_indirect          (HL+C)                  o_compireg
//stack_ind_pre_inc     (+SP)                   o_stkstp
//stack_ind_post_dec    (SP-)                   o_stkstp
//stack_ind_displac     (SP+d)                  o_disp
//stack_immediate_inc/dec LD SP,SP+/-d          o_stkimm
//PC_relative_ind       (PC+A)                  o_compireg
//--mem direct
//direct8               (x)                     o_mem
//direct16              (vw)                    o_mem

//--reg addr
/////
//--imm addr
/////
//--PC relative
////
//--absolute
////
//--vector addr
//vect_addr             (addr x2 + 0xFFA0)

//--direct bit addr
//regbit                reg.b
//membit                (mem_addr).b
//--indir bit addr
//indbit                (mem_addr).A


//------------------------------------------------------------------------
// a list of the processor registers
enum T870C_registers { rNULLReg,
        rA, rW, rC, rB, rE, rD, rL, rH,
        rWA, rBC, rDE, rHL, rIX, rIY, rSP,
        rPC,
        rVcs, rVds            // these 2 registers are required by the IDA kerne        
        };

// all sorts of different phrases
enum T870C_phrases{rNULLPh,
        fCnEQ,fCnNE,fCnLT,fCnGE,fCnLE,fCnGT,fCnT,fCnF,          //conditions
        fCnM,fCnP,fCnSLT,fCnSGE,fCnSLE,fCnSGT,fCnVS,fCnVC,      //conditions
        fCnCS,              //same as fCnLT
        fFlCF,fPSW,fRBS,    //flags
        fVectAddr};         //spec addressing
        //eq=Z ne=NZ lt=CS ge=CC
        // fCF,fCLT,fCLE,fCULE,fCPE,fCMI,fCZ,fCC,
        // fCT,fCGE,fCGT,fCUGT,fCPO,fCPL,fCNZ,fCNC,
        // fSF,fSF1,
        // fSR, fPC};
        
enum T870C_bits{bNull,
    b0,b1,b2,b3,b4,b5,b6,b7,bA};
    
enum T870C_stksteps{sNull,
    sInc, sDec};
        
//enum T870C_conditions{fNullCond,
//        fCnEQ,fCnNE,fCnLT,fCnGE,fCnLE,fCnGT,fCnT,fCnF};

extern char deviceparams[];
extern char device[];

//------------------------------------------------------------------------
ea_t map_addr(ea_t base, int16 offs, char cmdsiz);

void idaapi T870C_header(void);
void idaapi T870C_footer(void);

void idaapi T870C_segstart(ea_t ea);

int  idaapi T870C_ana(void);
int  idaapi T870C_emu(void);
void idaapi T870C_out(void);
bool idaapi T870C_outop(op_t &op);

void idaapi T870C_data(ea_t ea);

bool create_func_frame(func_t *pfn);

#endif
