/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The AArch64 hybrid: the aarch64 backend and TCTI in one build.
 *
 * Register numbers are aarch64's, and TCTI's are the same numbers under its
 * own names: R0-R31 are 0-31, V0-V31 are 32-63 in both. What differs between
 * the two is which registers env and the frame live in, so TCG_AREG0 and
 * TCG_REG_CALL_STACK are not enumerators here: tcg-target.c.inc defines them
 * for each backend in turn, and leaves the active one's for tcg.c.
 */

#ifndef AARCH64_HYBRID_TCG_TARGET_H
#define AARCH64_HYBRID_TCG_TARGET_H

#define TCG_TARGET_INSN_UNIT_SIZE  4
#define MAX_CODE_GEN_BUFFER_SIZE  ((size_t)-1)

typedef enum {
    TCG_REG_X0, TCG_REG_X1, TCG_REG_X2, TCG_REG_X3,
    TCG_REG_X4, TCG_REG_X5, TCG_REG_X6, TCG_REG_X7,
    TCG_REG_X8, TCG_REG_X9, TCG_REG_X10, TCG_REG_X11,
    TCG_REG_X12, TCG_REG_X13, TCG_REG_X14, TCG_REG_X15,
    TCG_REG_X16, TCG_REG_X17, TCG_REG_X18, TCG_REG_X19,
    TCG_REG_X20, TCG_REG_X21, TCG_REG_X22, TCG_REG_X23,
    TCG_REG_X24, TCG_REG_X25, TCG_REG_X26, TCG_REG_X27,
    TCG_REG_X28, TCG_REG_X29, TCG_REG_X30,

    /* X31 is either the stack pointer or zero, depending on context.  */
    TCG_REG_SP = 31,
    TCG_REG_XZR = 31,

    TCG_REG_V0 = 32, TCG_REG_V1, TCG_REG_V2, TCG_REG_V3,
    TCG_REG_V4, TCG_REG_V5, TCG_REG_V6, TCG_REG_V7,
    TCG_REG_V8, TCG_REG_V9, TCG_REG_V10, TCG_REG_V11,
    TCG_REG_V12, TCG_REG_V13, TCG_REG_V14, TCG_REG_V15,
    TCG_REG_V16, TCG_REG_V17, TCG_REG_V18, TCG_REG_V19,
    TCG_REG_V20, TCG_REG_V21, TCG_REG_V22, TCG_REG_V23,
    TCG_REG_V24, TCG_REG_V25, TCG_REG_V26, TCG_REG_V27,
    TCG_REG_V28, TCG_REG_V29, TCG_REG_V30, TCG_REG_V31,

    /* aarch64's aliases.  */
    TCG_REG_FP = TCG_REG_X29,
    TCG_REG_LR = TCG_REG_X30,

    /* TCTI's names for the same general registers.  */
    TCG_REG_R0 = 0, TCG_REG_R1, TCG_REG_R2, TCG_REG_R3,
    TCG_REG_R4, TCG_REG_R5, TCG_REG_R6, TCG_REG_R7,
    TCG_REG_R8, TCG_REG_R9, TCG_REG_R10, TCG_REG_R11,
    TCG_REG_R12, TCG_REG_R13, TCG_REG_R14, TCG_REG_R15,
    TCG_REG_R16, TCG_REG_R17, TCG_REG_R18, TCG_REG_R19,
    TCG_REG_R20, TCG_REG_R21, TCG_REG_R22, TCG_REG_R23,
    TCG_REG_R24, TCG_REG_R25, TCG_REG_R26, TCG_REG_R27,
    TCG_REG_R28, TCG_REG_R29, TCG_REG_R30, TCG_REG_R31,
} TCGReg;

#define TCG_REG_ZERO TCG_REG_XZR

#define TCG_TARGET_NB_REGS 64

/* TCTI's: it uses R0-R15 and V16-V31. */
#define TCG_TARGET_GP_REGS 16
#define TCG_MASK_GP_REGISTERS      0xFFFFul
#define TCG_MASK_VECTOR_REGISTERS  0xFFFF000000000000ul

#endif /* AARCH64_HYBRID_TCG_TARGET_H */
