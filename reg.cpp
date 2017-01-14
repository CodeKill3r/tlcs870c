/*
 *      TLCS870/c processor module for IDA.
 *      Copyright (c) 2016 M¡t© Sebåk < smfinc.org{at}gmail.com >
 *      Freeware.
 */

#include "tosh.hpp"
#include <fpro.h>
#include <diskio.hpp>
#include <entry.hpp>
#include <srarea.hpp>


//--------------------------------------------------------------------------
// register list
static const char *const RegNames[] =
{
        // null
        "",
        // 8 bit registers
        "A","W","C","B","E","D","L","H",
        // 16bit registers
        "WA","BC","DE","HL","IX","IY","IZ","SP",

        // virtual registers for code and data segments
        "cs","ds"
};

netnode helper;

char device[MAXSTR] = "";
static size_t numports = 0;
static ioport_t *ports = NULL;

#include <iocommon.cpp>

//--------------------------------------------------------------------------
const char * idaapi set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL ) return IDPOPT_BADKEY;
  char cfgfile[QMAXFILE];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( choose_ioport_device(cfgfile, device, sizeof(device), NULL) )
    set_device_name(device, IORESP_PORT|IORESP_INT);
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
static int idaapi notify(processor_t::idp_notify msgid, ...)
{
  va_list va;
  va_start(va, msgid);
// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  switch ( msgid ){
    case processor_t::init:
      inf.mf = 0;
      inf.s_genflags |= INFFL_LZERO;
      helper.create("$ TLCS870C");
      break;

    case processor_t::term:
      free_ioports(ports, numports);
    default:
      break;

    case processor_t::newfile:
      //Displays DLG. processor box, and allows you to select, read for the selected
      //CPU information from cfg. As a matter of information signs and ports regstry
      {
        char cfgfile[QMAXFILE];
        get_cfg_filename(cfgfile, sizeof(cfgfile));
        if ( choose_ioport_device(cfgfile, device, sizeof(device), NULL) )
          set_device_name(device, IORESP_ALL);
      }
      break;

	//case processor_t::oldfile:  // old file loaded
 //     {
 //       char buf[MAXSTR];
 //       if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
 //         set_device_name(buf, IORESP_NONE);
 //     }
 //     break;

     case processor_t::newprc:{
           char buf[MAXSTR];
           if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
             set_device_name(buf, IORESP_PORT);
         }
         break;

     case processor_t::newseg:{
                 segment_t *s = va_arg(va, segment_t *);
                 // Set default value of DS register for all segments
                 set_default_dataseg(s->sel);
                 }
                 break;
  }
  va_end(va);
  return(1);
}

//-----------------------------------------------------------------------
//      Checkarg data. Common for all assemblers. Not good.
//-----------------------------------------------------------------------
static const char *operdim[15] = {  // ALWAYS AND TOP 15
     "(", ")", "!", "-", "+", "%",
     "\\", "/", "*", "&", "|", "^", "<<", ">>", NULL};
//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const asm_t pseudosam = {
  AS_COLON | AS_UDATA | ASH_HEXF3 ,
  0,
  "Generic IAR-style assembler",        // assembly name
  0,                                    // room in help'e
  NULL,                                 // AutoCaption
  NULL,                                 // array is not ispozuetsya instructions
  "org",                                // section ORG
  "end",                                // section end

  ";",                                  // comment string
  '\"',                                  // string delimiter
  '\'',                                 // char delimiter
  "\\\"'",                              // special symbols in char and string constants

  "db",                                 // ascii string directive
  "db",                                 // byte directive
  "dw",                                 // word directive
  "dl",                                 // dword  (4 bytes)
  NULL,                                 // qword  (8 bytes)
  NULL,                                 // oword  (16 bytes)
  NULL,                                 // float  (4 bytes)
  NULL,                                 // double (8 bytes)
  NULL,                                 // tbyte  (10/12 bytes)
  NULL,                                 // packed decimal real
  "#d dup(#v)",                         // arrays (#h,#d,#v,#s(...)
  "db ?",                               // uninited arrays
  ".equ",                               // equ
  NULL,                                 // seg prefix
  NULL,                              // control
  NULL,                                 // atomprefix
  operdim,                              // array operations
  NULL,                                 // transcoded into ASCII
  "$",                                  // Current IP
  NULL,                                 // func_header
  NULL,                                 // func_footer
  NULL,                                 // "public" name keyword
  NULL,                                 // "weak"   name keyword
  NULL,                                 // "extrn"  name keyword
                                        // .extern directive requires an explicit object size
  NULL,                                 // "comm" (communal variable)
  NULL,                                 // get_type_name
  "align"                               // "align" keyword
  ,'(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
  AS2_BRACE,
};

// List assembler
static const asm_t *const asms[] = { &pseudosam, NULL };
//-----------------------------------------------------------------------
#define FAMILY "Toshiba TLCS-870/C series:"
static const char *const shnames[] = { "TLCS870C", NULL };
static const char *const lnames[] = { FAMILY"Toshiba TLCS870/C", NULL };

//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//      - if an instruction has the "return" opcode, its autogenerated label
//        will be "locret" rather than "loc".
//      - IDA will use the first "return" opcode to create empty subroutines.

static const uchar retcode_1[] = { 0xFA };    // ret
static const uchar retcode_2[] = { 0xFB };    // reti
static const uchar retcode_3[] = { 0xE8, 0xFB };    // retn
static const uchar retcode_4[] = { 0xE9, 0xFB };    // retn
static const uchar retcode_5[] = { 0xEA, 0xFB };    // retn
static const uchar retcode_6[] = { 0xEB, 0xFB };    // retn
static const uchar retcode_7[] = { 0xEC, 0xFB };    // retn
static const uchar retcode_8[] = { 0xED, 0xFB };    // retn
static const uchar retcode_9[] = { 0xEE, 0xFB };    // retn
static const uchar retcode_10[] = { 0xEF, 0xFB };    // retn
static const bytes_t retcodes[] = {
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { sizeof(retcode_4), retcode_4 },
 { sizeof(retcode_5), retcode_5 },
 { sizeof(retcode_6), retcode_6 },
 { sizeof(retcode_7), retcode_7 },
 { sizeof(retcode_8), retcode_8 },
 { sizeof(retcode_9), retcode_9 },
 { sizeof(retcode_10), retcode_10 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH = {
  IDP_INTERFACE_VERSION,        // version
  0x870c,                       // id number
  PRN_HEX,                      // no special features supported
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte

  shnames,               // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  T870C_header,                  // generate the disassembly header
  T870C_footer,                  // generate the disassembly footer

  T870C_segstart,                // generate a segment declaration (start of segment)
  std_gen_segm_footer,          // generate a segment footer (end of segment)

  NULL,                         // generate 'assume' directives

  T870C_ana,                     // analyze an instruction and fill the 'cmd' structure
  T870C_emu,                     // emulate an instruction

  T870C_out,                     // generate a text representation of an instruction
  T870C_outop,                   // generate a text representation of an operand
  T870C_data,                    // generate a text representation of a data item
  NULL,                         // compare operands
  NULL,                         // can an operand have a type?

  qnumber(RegNames),            // Number of registers
  RegNames,                     // Regsiter names
  NULL,                         // get abstract register

  0,                            // Number of register files
  NULL,                         // Register file names
  NULL,                         // Register descriptions
  NULL,                         // Pointer to CPU registers
  rVcs,rVds,
  2,                            // size of a segment register
  rVcs,rVds,
  NULL,                         // No known code start sequences
  retcodes,                     // 'Return' instruction codes
  0,T870C_last,                  // first and last instructions
  Instructions,                 // instructions array name
  NULL,                         // int  (*is_far_jump)(int icode);
  NULL,                         // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                         // search switch
  NULL,                         // MAP-file generator
  NULL,                         // string -> Address
  NULL,                         // an offset in the stack test
  NULL,                         // creating a frame function
  NULL,                         // Get size of function return address in bytes (2/4 by default)
  NULL,                         // creating line descriptions stack variable
  gen_spcdef,                   // text generator for ....
  T870C_ret,                    // Icode to return to the team
  NULL, //set_idp_options,                         // transfer options in the IDP
  NULL,							// Is the instruction created only for alignment purposes?
  NULL,                          // micro virtual mashine
  //,0                            // fixup bit's
};
