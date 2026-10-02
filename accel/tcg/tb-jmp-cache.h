/*
 * The per-CPU TranslationBlock jump cache.
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_TB_JMP_CACHE_H
#define ACCEL_TCG_TB_JMP_CACHE_H

#include "qemu/rcu.h"
#include "exec/cpu-common.h"

#define TB_JMP_CACHE_BITS 14
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

/*
 * Invalidated in parallel; all accesses to 'tb' must be atomic.
 * A valid entry is read/written by a single CPU, therefore there is
 * no need for qatomic_rcu_read() and pc is always consistent with a
 * non-NULL value of 'tb'.  Strictly speaking pc is only needed for
 * CF_PCREL, but it's used always for simplicity.
 *
 * Two-way: a pc's TB is in entry tb_jmp_cache_hash_func(pc), or in its
 * partner, that index ^ 1, which is in the same page's group. Hot
 * indirect-jump targets otherwise evict each other: in a Cycles render,
 * nearly every miss found another pc in the entry.
 */
typedef struct CPUJumpCache {
    struct rcu_head rcu;
    struct {
        TranslationBlock *tb;
        vaddr pc;
    } array[TB_JMP_CACHE_SIZE];
} CPUJumpCache;

/*
 * Add @tb for @pc at @h, the pair's first way: into a free way, else into
 * the first after moving its entry to the second, so that two hot TBs
 * sharing the pair both stay.
 */
static inline void tb_jmp_cache_insert(CPUJumpCache *jc, uint32_t h,
                                       vaddr pc, TranslationBlock *tb)
{
    if (qatomic_read(&jc->array[h].tb) && !qatomic_read(&jc->array[h ^ 1].tb)) {
        h ^= 1;
    } else if (qatomic_read(&jc->array[h].tb)) {
        jc->array[h ^ 1].pc = jc->array[h].pc;
        qatomic_set(&jc->array[h ^ 1].tb, qatomic_read(&jc->array[h].tb));
    }
    jc->array[h].pc = pc;
    qatomic_set(&jc->array[h].tb, tb);
}

#endif /* ACCEL_TCG_TB_JMP_CACHE_H */
