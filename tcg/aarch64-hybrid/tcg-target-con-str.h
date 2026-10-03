/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Define the AArch64 hybrid's operand constraint letters: aarch64's and
 * TCTI's. They are read once, at startup, so 'r' and 'w' mean the backend
 * active then. (A switch between backends would have to read them again.)
 */

/*
 * Define constraint letters for register sets:
 * REGS(letter, register_mask)
 */
#if defined(CONFIG_TCG_HYBRID_RUNTIME)
REGS('r', tcg_tcti_active() ? TCG_MASK_GP_REGISTERS : ALL_GENERAL_REGS)
REGS('w', tcg_tcti_active() ? TCG_MASK_VECTOR_REGISTERS : ALL_VECTOR_REGS)
#elif defined(CONFIG_TCG_THREADED_INTERPRETER)
REGS('r', TCG_MASK_GP_REGISTERS)
REGS('w', TCG_MASK_VECTOR_REGISTERS)
#else
REGS('r', ALL_GENERAL_REGS)
REGS('w', ALL_VECTOR_REGS)
#endif

/* TCTI's: the fixed data registers of the 128-bit guest load/store gadgets. */
REGS('a', 1u << TCG_REG_R0)
REGS('b', 1u << TCG_REG_R1)
REGS('c', 1u << TCG_REG_R2)
REGS('d', 1u << TCG_REG_R3)

/*
 * Define constraint letters for constants:
 * CONST(letter, TCG_CT_CONST_* bit set)
 */
/* aarch64's. */
CONST('A', TCG_CT_CONST_AIMM)
CONST('C', TCG_CT_CONST_CMP)
CONST('L', TCG_CT_CONST_LIMM)
CONST('M', TCG_CT_CONST_MONE)
CONST('O', TCG_CT_CONST_ORRI)
CONST('N', TCG_CT_CONST_ANDI)
CONST('Z', TCG_CT_CONST_ZERO)
/* TCTI's: simple 64-bit immediates. */
CONST('I', 0xFFFFFFFFFFFFFFFF)
