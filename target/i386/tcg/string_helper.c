/*
 * x86 REP MOVS and REP STOS, a page at a time
 *
 * tctiSH: the translator runs a repeated string instruction one element per
 * trip around a loop, with a softmmu access for each element. For REP MOVSB,
 * which is how Linux copies to and from user space on any CPU with ERMS, that
 * is a full trip per byte. These helpers do the same work with memmove() and
 * memset() on host memory, as much of a page as both sides allow at a time.
 *
 * The approach is that of the Arm FEAT_MOPS helpers (copy_step and set_step in
 * target/arm/tcg/helper-a64.c), which are architected memcpy and memset with
 * the same need to be interruptible and restartable part way through:
 *
 * - The bulk path asks tlb_vaddr_to_host() for host memory, which never
 *   faults: it answers only for plain RAM already in the TLB, and not for I/O,
 *   watchpoints or clean code pages.
 * - Anything else moves one element through the ordinary softmmu accessors,
 *   which fill the TLB, fault precisely, fire watchpoints, and invalidate the
 *   TBs of a code page written to. The next step then usually finds host
 *   memory.
 * - RCX, RSI and RDI are written back after every step, so a fault restarts
 *   the instruction exactly where it stopped, as hardware does.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu-common.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/probe.h"
#include "helper-tcg.h"

/*
 * How much one call may move before handing back to the main loop, so that a
 * REP over gigabytes still lets interrupts in. Pending ones are checked after
 * every step as well; this bounds the case where none arrive.
 */
#define REP_BULK_BUDGET (1 * MiB)

/* Bytes from addr to the end of its page. */
static uint64_t page_room(vaddr addr)
{
    return TARGET_PAGE_SIZE - (addr & ~TARGET_PAGE_MASK);
}

static uint64_t load_element(CPUX86State *env, vaddr addr, MemOp ot,
                             int mmu_idx, uintptr_t ra)
{
    switch (ot) {
    case MO_8:
        return cpu_ldub_mmuidx_ra(env, addr, mmu_idx, ra);
    case MO_16:
        return cpu_lduw_le_mmuidx_ra(env, addr, mmu_idx, ra);
    case MO_32:
        return cpu_ldl_le_mmuidx_ra(env, addr, mmu_idx, ra);
    default:
        return cpu_ldq_le_mmuidx_ra(env, addr, mmu_idx, ra);
    }
}

static void store_element(CPUX86State *env, vaddr addr, uint64_t value,
                          MemOp ot, int mmu_idx, uintptr_t ra)
{
    switch (ot) {
    case MO_8:
        cpu_stb_mmuidx_ra(env, addr, value, mmu_idx, ra);
        break;
    case MO_16:
        cpu_stw_le_mmuidx_ra(env, addr, value, mmu_idx, ra);
        break;
    case MO_32:
        cpu_stl_le_mmuidx_ra(env, addr, value, mmu_idx, ra);
        break;
    default:
        cpu_stq_le_mmuidx_ra(env, addr, value, mmu_idx, ra);
        break;
    }
}

/* Fills host memory with count elements of value. */
static void fill_host(uint8_t *mem, uint64_t value, MemOp ot, uint64_t count)
{
    const uint64_t bytes = count << ot;
    uint8_t byte = value;

    /* Every byte the same, which covers zeroing: memset does it all. */
    if (value == byte * (UINT64_MAX / 0xff >> (64 - (8 << ot)))) {
        memset(mem, byte, bytes);
        return;
    }

    for (uint64_t at = 0; at < bytes; at += 1 << ot) {
        switch (ot) {
        case MO_16:
            stw_le_p(mem + at, value);
            break;
        case MO_32:
            stl_le_p(mem + at, value);
            break;
        default:
            stq_le_p(mem + at, value);
            break;
        }
    }
}

/* Moves RCX, RSI and RDI on by count elements. */
static void advance(CPUX86State *env, uint64_t count, MemOp ot, bool source)
{
    env->regs[R_ECX] -= count;
    env->regs[R_EDI] += count << ot;
    if (source) {
        env->regs[R_ESI] += count << ot;
    }
}

/*
 * REP MOVS with a 64-bit address size, forwards. src_seg is the source's
 * segment when it has a base (FS or GS), or -1; in 64-bit mode no other
 * segment does, ES:RDI included.
 *
 * Returns REP_BULK_DONE once RCX is zero, REP_BULK_YIELD to have the
 * instruction re-executed from the main loop with what is left, and
 * REP_BULK_SLOW, without having done anything, for a backwards copy, which the
 * translator's loop does instead.
 */
uint32_t helper_rep_movs(CPUX86State *env, uint32_t ot, uint32_t mmu_idx,
                         int32_t src_seg)
{
    const uintptr_t ra = GETPC();
    const vaddr base = src_seg >= 0 ? env->segs[src_seg].base : 0;
    uint64_t budget = REP_BULK_BUDGET;

    if (env->df != 1) {
        return REP_BULK_SLOW;
    }

    while (env->regs[R_ECX] != 0) {
        const vaddr src = base + env->regs[R_ESI];
        const vaddr dst = env->regs[R_EDI];
        uint64_t count = MIN(page_room(src), page_room(dst)) >> ot;
        uint8_t *rmem = NULL;
        uint8_t *wmem = NULL;

        count = MIN(count, env->regs[R_ECX]);

        /* An element straddling a page on either side goes the slow way. */
        if (count != 0) {
            rmem = tlb_vaddr_to_host(env, src, MMU_DATA_LOAD, mmu_idx);
            wmem = tlb_vaddr_to_host(env, dst, MMU_DATA_STORE, mmu_idx);
        }

        if (unlikely(!rmem || !wmem)) {
            store_element(env, dst, load_element(env, src, ot, mmu_idx, ra),
                          ot, mmu_idx, ra);
            advance(env, 1, ot, true);
            budget -= MIN(budget, 1 << ot);
        } else {
            /*
             * A forward REP MOVS onto a destination just above its source
             * repeats a pattern, element by element, where memmove() would
             * copy the original. Steps no longer than the distance between
             * them give exactly the element-by-element result. Compared as
             * host pointers, since two guest addresses can be the same page.
             */
            if (wmem > rmem && (uint64_t)(wmem - rmem) < count << ot) {
                count = MAX((uint64_t)(wmem - rmem) >> ot, 1);
            }

            memmove(wmem, rmem, count << ot);
            advance(env, count, ot, true);
            budget -= MIN(budget, count << ot);
        }

        if (env->regs[R_ECX] != 0 &&
            (budget == 0 || cpu_loop_exit_requested(env_cpu(env)))) {
            return REP_BULK_YIELD;
        }
    }

    return REP_BULK_DONE;
}

/* REP STOS, as helper_rep_movs. */
uint32_t helper_rep_stos(CPUX86State *env, uint32_t ot, uint32_t mmu_idx)
{
    const uintptr_t ra = GETPC();
    const uint64_t value = env->regs[R_EAX] & MAKE_64BIT_MASK(0, 8 << ot);
    uint64_t budget = REP_BULK_BUDGET;

    if (env->df != 1) {
        return REP_BULK_SLOW;
    }

    while (env->regs[R_ECX] != 0) {
        const vaddr dst = env->regs[R_EDI];
        uint64_t count = MIN(page_room(dst) >> ot, env->regs[R_ECX]);
        uint8_t *wmem = NULL;

        if (count != 0) {
            wmem = tlb_vaddr_to_host(env, dst, MMU_DATA_STORE, mmu_idx);
        }

        if (unlikely(!wmem)) {
            store_element(env, dst, value, ot, mmu_idx, ra);
            advance(env, 1, ot, false);
            budget -= MIN(budget, 1 << ot);
        } else {
            fill_host(wmem, value, ot, count);
            advance(env, count, ot, false);
            budget -= MIN(budget, count << ot);
        }

        if (env->regs[R_ECX] != 0 &&
            (budget == 0 || cpu_loop_exit_requested(env_cpu(env)))) {
            return REP_BULK_YIELD;
        }
    }

    return REP_BULK_DONE;
}
