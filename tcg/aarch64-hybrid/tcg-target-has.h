/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Define target-specific opcode support for the AArch64 hybrid: what the two
 * backends agree on once, and the rest as the active backend has it.
 */

#ifndef TCG_TARGET_HAS_H
#define TCG_TARGET_HAS_H

#include "host/cpuinfo.h"

/* aarch64's, which its tcg-target.c.inc reads. */
#define have_lse    (cpuinfo & CPUINFO_LSE)
#define have_lse2   (cpuinfo & CPUINFO_LSE2)
#define have_cssc   (cpuinfo & CPUINFO_CSSC)

#define TCG_TARGET_HAS_extr_i64_i32     0

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

#if defined(CONFIG_TCG_HYBRID_RUNTIME)
/* Whichever is active's; both are below. */
#include "tcg/hybrid.h"
#define TCG_TARGET_HAS_qemu_ldst_i128 \
    (tcg_tcti_active() ? (cpuinfo & CPUINFO_LSE2) != 0 : 1)
#define TCG_TARGET_HAS_ordered_ldst \
    (tcg_tcti_active() && \
     (cpuinfo & (CPUINFO_LSE2 | CPUINFO_LRCPC)) == (CPUINFO_LSE2 | CPUINFO_LRCPC))
#define TCG_TARGET_HAS_tst              (!tcg_tcti_active())
#define TCG_TARGET_HAS_tst_vec          (!tcg_tcti_active())
#define TCG_TARGET_extract_valid(type, ofs, len) \
    (!tcg_tcti_active() || \
     ((ofs) == 0 && ((len) == 8 || (len) == 16 || \
                     ((len) == 32 && (type) == TCG_TYPE_I64))))
#define TCG_TARGET_sextract_valid(type, ofs, len) \
    TCG_TARGET_extract_valid(type, ofs, len)
#define TCG_TARGET_deposit_valid(type, ofs, len)   (!tcg_tcti_active())
#elif defined(CONFIG_TCG_THREADED_INTERPRETER)
/* TCTI's; see ../aarch64-tcti/tcg-target-has.h for why. */
#define TCG_TARGET_HAS_qemu_ldst_i128   (cpuinfo & CPUINFO_LSE2)
#define TCG_TARGET_HAS_ordered_ldst \
    ((cpuinfo & (CPUINFO_LSE2 | CPUINFO_LRCPC)) == (CPUINFO_LSE2 | CPUINFO_LRCPC))
#define TCG_TARGET_HAS_tst              0
#define TCG_TARGET_HAS_tst_vec          0
#define TCG_TARGET_extract_valid(type, ofs, len) \
    ((ofs) == 0 && ((len) == 8 || (len) == 16 || \
                    ((len) == 32 && (type) == TCG_TYPE_I64)))
#define TCG_TARGET_sextract_valid(type, ofs, len) \
    TCG_TARGET_extract_valid(type, ofs, len)
#define TCG_TARGET_deposit_valid(type, ofs, len)   0
#else
/* aarch64's; see ../aarch64/tcg-target-has.h. */
#ifdef CONFIG_USER_ONLY
#define TCG_TARGET_HAS_qemu_ldst_i128   have_lse2
#else
#define TCG_TARGET_HAS_qemu_ldst_i128   1
#endif
#define TCG_TARGET_HAS_tst              1
#define TCG_TARGET_HAS_tst_vec          1
#define TCG_TARGET_extract_valid(type, ofs, len)   1
#define TCG_TARGET_sextract_valid(type, ofs, len)  1
#define TCG_TARGET_deposit_valid(type, ofs, len)   1
#endif

#endif
