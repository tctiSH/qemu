/* SPDX-License-Identifier: MIT */
/*
 * Constants shared between the TCTI backend and its generated gadgets.
 *
 * Included by the generated gadget sources that need a value only the C
 * compiler can work out, and by tcg-target.c.inc so that both sides agree.
 */

#ifndef TCTI_GADGET_DEFS_H
#define TCTI_GADGET_DEFS_H

#include "qemu/osdep.h"
#include "hw/core/cpu.h"

/*
 * The offset from env of the CPUTLBDescFast for mmu_idx: what
 * tlb_mask_table_ofs() returns, as a constant expression, so that a gadget
 * can take it as an "i" asm operand. Must track mmuidx_to_fast_index().
 */
#define TCTI_TLB_FAST_OFS(mmu_idx)                                      \
    ((int)(offsetof(CPUNegativeOffsetState,                             \
                    tlb.f[NB_MMU_MODES - 1 - (mmu_idx)]) -              \
           sizeof(CPUNegativeOffsetState)))

/*
 * The MMU indices that have TLB fast-path gadgets, which are 0 to this minus
 * one. Must match QEMU_TLB_FAST_MMU_INDICES in tcti-gadget-gen.py.
 */
#define TCTI_TLB_FAST_MMU_INDICES 6

/* LDP takes a signed, 8-byte scaled 7-bit offset. */
QEMU_BUILD_BUG_ON(TCTI_TLB_FAST_OFS(TCTI_TLB_FAST_MMU_INDICES - 1) < -512);

#endif /* TCTI_GADGET_DEFS_H */
