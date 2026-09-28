/*
 * x86's TB lookup state, inline.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_I386_TCG_TB_CPU_STATE_H
#define TARGET_I386_TCG_TB_CPU_STATE_H

#include "cpu.h"
#include "accel/tcg/tb-cpu-state.h"

/*
 * What x86_get_tb_cpu_state() returns, for callers that can see CPUX86State:
 * accel/tcg/cpu-exec.c when it is compiled for this target, where it runs on
 * every TB lookup. See the comment there.
 */
static inline TCGTBCPUState x86_tb_cpu_state(CPUState *cs)
{
    CPUX86State *env = cpu_env(cs);
    uint32_t flags, cs_base;
    vaddr pc;

    flags = env->hflags |
        (env->eflags & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK | AC_MASK));
    if (env->hflags & HF_CS64_MASK) {
        cs_base = 0;
        pc = env->eip;
    } else {
        cs_base = env->segs[R_CS].base;
        pc = (uint32_t)(cs_base + env->eip);
    }

    return (TCGTBCPUState){ .pc = pc, .flags = flags, .cs_base = cs_base };
}

#endif
