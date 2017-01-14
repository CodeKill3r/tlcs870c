/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 2016 Máté Sebõk < smfinc.org{at}gmail.com >
 *      Freeware.
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

// List of instructions
extern instruc_t Instructions[];

//
enum nameNum ENUM_SIZE(uint16)
{
T870C_null = 0,           // Unknown Operation
T870C_ld,
T870C_ldw,
T870C_push,
T870C_pop,
T870C_xch,

T870C_cmp,
T870C_add,
T870C_addc,
T870C_sub,
T870C_subb,
T870C_and,
T870C_or,
T870C_xor,
T870C_inc,
T870C_dec,
T870C_daa,
T870C_das,
T870C_mul,
T870C_div,
T870C_neg,

T870C_shlc,
T870C_shrc,
T870C_rolc,
T870C_rorc,
T870C_shlca,
T870C_shrca,
T870C_swap,
T870C_rold,
T870C_rord,

T870C_set,
T870C_clr,
T870C_test,
T870C_cpl,
T870C_di,
T870C_ei,

T870C_jrs,
T870C_jr,
T870C_jr_cond,
T870C_jp,

T870C_callv,
T870C_call,
T870C_ret,
T870C_reti,
T870C_retn,

T870C_swi,
T870C_nop,

T870C_last
};

#endif
