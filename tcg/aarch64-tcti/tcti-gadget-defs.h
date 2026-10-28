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
#include "exec/translation-block.h"
#include "tcg/lookup-key.h"

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
 * one. Must match QEMU_TLB_FAST_MMU_INDICES in tcti_memory.py.
 */
#define TCTI_TLB_FAST_MMU_INDICES 6

/* LDP takes a signed, 8-byte scaled 7-bit offset. */
QEMU_BUILD_BUG_ON(TCTI_TLB_FAST_OFS(TCTI_TLB_FAST_MMU_INDICES - 1) < -512);

/*
 * The guest page size the fast-path gadgets are built for. TCG's common code
 * learns the guest's only at run time, so the backend uses a gadget only
 * where the two match (tcti_has_fast_path()).
 */
#define TCTI_TLB_PAGE_BITS 12
#define TCTI_TLB_PAGE_MASK (~(uint64_t)0 << TCTI_TLB_PAGE_BITS)

/* A guest address shifted right by this, and masked, is its entry's offset. */
#define TCTI_TLB_INDEX_SHIFT (TCTI_TLB_PAGE_BITS - CPU_TLB_ENTRY_BITS)

/*
 * The word every TB checks at its start, negative when an exit has been
 * requested: see gen_tb_start(). The goto_tb gadgets read it with LDUR.
 */
#define TCTI_EXIT_REQUEST_OFS                                           \
    ((int)(offsetof(CPUState, neg.icount_decr.u32) - sizeof(CPUState)))

QEMU_BUILD_BUG_ON(TCTI_EXIT_REQUEST_OFS < -256);

/* One LDP loads a CPUTLBDescFast's mask and table, in this order. */
QEMU_BUILD_BUG_ON(offsetof(CPUTLBDescFast, mask) != 0);
QEMU_BUILD_BUG_ON(offsetof(CPUTLBDescFast, table) != 8);

/* A gadget loads the comparators and the addend as 64-bit words. */
QEMU_BUILD_BUG_ON(sizeof_field(CPUTLBEntry, addr_read) != 8);
QEMU_BUILD_BUG_ON(sizeof_field(CPUTLBEntry, addr_write) != 8);
QEMU_BUILD_BUG_ON(sizeof_field(CPUTLBEntry, addend) != 8);

/*
 * The lookup_tb gadget's constants: a TCGLookupKey field's offset, which it
 * loads in pairs; tb_jmp_cache_hash_func() for 4 KiB pages; and the
 * TranslationBlock fields it compares, flags and cflags in one LDP.
 */
#define TCTI_LK(field) ((int)offsetof(TCGLookupKey, field))
#define TCTI_LK_HASH_SHIFT (TCG_LOOKUP_PAGE_BITS - TCG_LOOKUP_JC_BITS / 2)
#define TCTI_LK_PAGE_MASK                                               \
    ((1 << TCG_LOOKUP_JC_BITS) - (1 << (TCG_LOOKUP_JC_BITS / 2)))
#define TCTI_LK_ADDR_MASK ((1 << (TCG_LOOKUP_JC_BITS / 2)) - 1)

QEMU_BUILD_BUG_ON(TCTI_LK(extra_ofs) != TCTI_LK(flags_ofs) + 8);
QEMU_BUILD_BUG_ON(TCTI_LK(mode) != TCTI_LK(extra_mask) + 8);
QEMU_BUILD_BUG_ON(TCTI_LK(cflags_ofs) != TCTI_LK(pc_ofs) + 8);
QEMU_BUILD_BUG_ON(TCTI_LK(bp_ofs) != TCTI_LK(sstep_ofs) + 8);
QEMU_BUILD_BUG_ON(TCTI_LK(loglevel) != TCTI_LK(one_insn_per_tb) + 8);
QEMU_BUILD_BUG_ON(offsetof(TranslationBlock, cflags) !=
                  offsetof(TranslationBlock, flags) + 4);
QEMU_BUILD_BUG_ON(sizeof_field(TranslationBlock, cs_base) != 8);

#endif /* TCTI_GADGET_DEFS_H */
