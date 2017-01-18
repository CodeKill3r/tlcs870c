/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 2016 Máté Sebõk < smfinc.org{at}gmail.com >
 *      Freeware.
 */

#include "tosh.hpp"

// Attention!!! command option to work with words
// Should go after _strogo_ byte version -
// Used to simplify analysis in ana.c

instruc_t Instructions[] = {
{ "",           0                               },      // Unknown Operation
{ "LD",         CF_USE1|CF_CHG1|CF_USE2         },      // Load  data
{ "LDW",        CF_USE1|CF_CHG1|CF_USE2         },      // Load  data
{ "PUSH",       CF_USE1                         },      // Push data
{ "POP",        CF_USE1|CF_CHG1                 },      // pop data
{ "XCH",        CF_USE1|CF_CHG1|CF_USE2|CF_CHG2 },      // xchg

{ "CMP",        CF_USE1|CF_USE2                 },      // cmp
{ "ADD",        CF_USE1|CF_CHG1|CF_USE2         },
{ "ADDC",       CF_USE1|CF_CHG1|CF_USE2         },      // add /w carry
{ "SUB",        CF_USE1|CF_CHG1|CF_USE2         },
{ "SUBB",       CF_USE1|CF_CHG1|CF_USE2         },      // sub /w carry
{ "AND",        CF_USE1|CF_CHG1|CF_USE2         },
{ "OR",         CF_USE1|CF_CHG1|CF_USE2         },
{ "XOR",        CF_USE1|CF_CHG1|CF_USE2         },
{ "INC",        CF_USE1|CF_CHG1                 },
{ "DEC",        CF_USE1|CF_CHG1                 },
{ "DAA",        CF_USE1|CF_CHG1                 },      //converts BCD sum after (binary)ADD/ADDC to BCD
{ "DAS",        CF_USE1|CF_CHG1                 },      //converts BCD result after (binary)SUB/SUBB to BCD
{ "MUL",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },
{ "DIV",        CF_USE1|CF_USE2|CF_CHG1         },
{ "NEG",        CF_USE1|CF_CHG1                 },

{ "SHLC",       CF_USE1|CF_CHG1                 },
{ "SHRC",       CF_USE1|CF_CHG1                 },
{ "ROLC",       CF_USE1|CF_CHG1                 },
{ "RORC",       CF_USE1|CF_CHG1                 },
{ "SHLCA",      CF_USE1|CF_CHG1                 },
{ "SHRCA",      CF_USE1|CF_CHG1                 },
{ "SWAP",       CF_USE1|CF_CHG1                 },
{ "ROLD",       CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },
{ "RORD",       CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },

{ "SET",        CF_USE1|CF_CHG1                 },
{ "CLR",        CF_USE1|CF_CHG1                 },
{ "TEST",       CF_USE1|CF_USE2                 },      // to JS & ~CF
{ "CPL",        CF_USE1|CF_CHG1                 },      // negate bit
{ "EI",         0                               },
{ "DI",         0                               },

{ "JRS",        CF_USE1|CF_USE2|CF_JUMP         },      // always conditional
{ "JR",         CF_USE1|        CF_JUMP|CF_STOP },
{ "JR",         CF_USE1|CF_USE2|CF_JUMP         },
{ "JP",         CF_USE1|        CF_JUMP|CF_STOP },

{ "CALLV",      CF_USE1|CF_CALL                 },
{ "CALL",       CF_USE1|CF_CALL                 },
{ "RET",        CF_STOP                         },
{ "RETI",       CF_STOP                         },
{ "RETN",       CF_STOP                         },

{ "SWI",        CF_STOP                         },
{ "NOP",        0                               }
};

CASSERT(qnumber(Instructions) == T870C_last);
