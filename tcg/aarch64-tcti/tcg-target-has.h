/* SPDX-License-Identifier: MIT */
/*
 * Define target-specific opcode support
 * Copyright (c) 2009, 2011 Stefan Weil
 */

#ifndef TCG_TARGET_HAS_H
#define TCG_TARGET_HAS_H

#include "host/cpuinfo.h"

/*
 * Since QEMU 10.1, whether a scalar op is supported is decided by its
 * TCGOutOp in tcg-target.c.inc; what is left here is what tcg.c and
 * tcg-op.c still read as macros.
 */

// Our 32-bit values live zero-extended in 64-bit registers, so truncation is
// a plain move.
#define TCG_TARGET_HAS_extr_i64_i32     0

// 128-bit guest loads and stores are one LDP/STP gadget, which is single-copy
// atomic only with LSE2; without it, TCG splits them or calls a helper.
#define TCG_TARGET_HAS_qemu_ldst_i128   (cpuinfo & CPUINFO_LSE2)

#define TCG_TARGET_HAS_tst              0

/*
 * extract and sextract are valid exactly where we have a single gadget for
 * them: the 8-, 16- and 32-bit zero and sign extensions. Everything else is
 * expanded by tcg-op.c into shifts and masks, as before 10.1 -- but these
 * three are what the ext8u..ext32s ops became, and without them each
 * extension would cost a constant load and an AND.
 */
#define TCG_TARGET_extract_valid(type, ofs, len) \
    ((ofs) == 0 && ((len) == 8 || (len) == 16 || \
                    ((len) == 32 && (type) == TCG_TYPE_I64)))
#define TCG_TARGET_sextract_valid(type, ofs, len) \
    TCG_TARGET_extract_valid(type, ofs, len)

// We don't currently support gadgets with more than three arguments,
// so we can't yet create deposit gadgets.
#define TCG_TARGET_deposit_valid(type, ofs, len)   0

//
// Supported optional vector instructions.
//

#define TCG_TARGET_HAS_v64              1
#define TCG_TARGET_HAS_v128             1
#define TCG_TARGET_HAS_v256             0

#define TCG_TARGET_HAS_andc_vec         1
#define TCG_TARGET_HAS_orc_vec          1
#define TCG_TARGET_HAS_nand_vec         0
#define TCG_TARGET_HAS_nor_vec          0
#define TCG_TARGET_HAS_eqv_vec          0
#define TCG_TARGET_HAS_not_vec          1
#define TCG_TARGET_HAS_neg_vec          1
#define TCG_TARGET_HAS_abs_vec          1
#define TCG_TARGET_HAS_roti_vec         0
#define TCG_TARGET_HAS_rots_vec         0
#define TCG_TARGET_HAS_rotv_vec         0
#define TCG_TARGET_HAS_shi_vec          1
#define TCG_TARGET_HAS_shs_vec          0
#define TCG_TARGET_HAS_shv_vec          1
#define TCG_TARGET_HAS_mul_vec          1
#define TCG_TARGET_HAS_sat_vec          1
#define TCG_TARGET_HAS_minmax_vec       1
#define TCG_TARGET_HAS_bitsel_vec       1
#define TCG_TARGET_HAS_cmpsel_vec       0
#define TCG_TARGET_HAS_tst_vec          0

#endif
