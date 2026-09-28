/* SPDX-License-Identifier: MIT */
/*
 * Define TCI target-specific operand constraints.
 * Copyright (c) 2021 Linaro
 */

/*
 * Define constraint letters for register sets:
 * REGS(letter, register_mask)
 */
REGS('r', TCG_MASK_GP_REGISTERS)
REGS('w', TCG_MASK_VECTOR_REGISTERS)

/*
 * Define constraint letters for constants:
 * CONST(letter, TCG_CT_CONST_* bit set)
 */

// Simple 64-bit immediates.
CONST('I', 0xFFFFFFFFFFFFFFFF)
