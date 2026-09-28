/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2009, 2011 Stefan Weil
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * This code implements a TCG which does not generate machine code for some
 * real target machine but which generates virtual machine code for an
 * interpreter. Interpreted pseudo code is slow, but it works on any host.
 *
 * Some remarks might help in understanding the code:
 *
 * "target" or "TCG target" is the machine which runs the generated code.
 * This is different to the usual meaning in QEMU where "target" is the
 * emulated machine. So normally QEMU host is identical to TCG target.
 * Here the TCG target is a virtual machine, but this virtual machine must
 * use the same word size like the real machine.
 * Therefore, we need both 32 and 64 bit virtual machines (interpreter).
 */

#ifndef TCG_TARGET_H
#define TCG_TARGET_H

#define TCG_TARGET_INSN_UNIT_SIZE        1
#define MAX_CODE_GEN_BUFFER_SIZE  ((size_t)-1)

// We're an interpreted target; even if we're JIT-compiling to our interpreter's
// weird psuedo-native bytecode. We'll indicate that we're intepreted.
#define TCG_TARGET_INTERPRETER 1

#include "tcg-target-has.h"

//
// Platform metadata.
//

// Number of registers available.
#define TCG_TARGET_NB_REGS 64

// Number of general purpose registers.
#define TCG_TARGET_GP_REGS 16

/* List of registers which are used by TCG. */
typedef enum {

    // General purpose registers.
    // Note that we name every _host_ register here; but don't 
    // necessarily use them; that's determined by the allocation order
    // and the number of registers setting above. These just give us the ability
    // to refer to these by name.
    TCG_REG_R0, TCG_REG_R1, TCG_REG_R2, TCG_REG_R3,
    TCG_REG_R4, TCG_REG_R5, TCG_REG_R6, TCG_REG_R7,
    TCG_REG_R8, TCG_REG_R9, TCG_REG_R10, TCG_REG_R11,
    TCG_REG_R12, TCG_REG_R13, TCG_REG_R14, TCG_REG_R15,
    TCG_REG_R16, TCG_REG_R17, TCG_REG_R18, TCG_REG_R19,
    TCG_REG_R20, TCG_REG_R21, TCG_REG_R22, TCG_REG_R23,
    TCG_REG_R24, TCG_REG_R25, TCG_REG_R26, TCG_REG_R27,
    TCG_REG_R28, TCG_REG_R29, TCG_REG_R30, TCG_REG_R31,

    // Register aliases.
    TCG_AREG0             = TCG_REG_R14,
    TCG_REG_CALL_STACK    = TCG_REG_R15,

    // Mask that refers to the GP registers.
    TCG_MASK_GP_REGISTERS = 0xFFFFul, 

    // Vector registers.
    TCG_REG_V0 = 32, TCG_REG_V1, TCG_REG_V2, TCG_REG_V3,
    TCG_REG_V4, TCG_REG_V5, TCG_REG_V6, TCG_REG_V7,
    TCG_REG_V8, TCG_REG_V9, TCG_REG_V10, TCG_REG_V11,
    TCG_REG_V12, TCG_REG_V13, TCG_REG_V14, TCG_REG_V15,
    TCG_REG_V16, TCG_REG_V17, TCG_REG_V18, TCG_REG_V19,
    TCG_REG_V20, TCG_REG_V21, TCG_REG_V22, TCG_REG_V23,
    TCG_REG_V24, TCG_REG_V25, TCG_REG_V26, TCG_REG_V27,
    TCG_REG_V28, TCG_REG_V29, TCG_REG_V30, TCG_REG_V31,

    // Mask that refers to the vector registers.
    TCG_MASK_VECTOR_REGISTERS = 0xFFFF000000000000ul, 

} TCGReg;

// We're interpreted, so we'll use our own code to run TB_EXEC.
#define HAVE_TCG_QEMU_TB_EXEC

void tci_disas(uint8_t opc);


#endif /* TCG_TARGET_H */
