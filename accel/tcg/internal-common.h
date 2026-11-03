/*
 * Internal execution defines for qemu (target agnostic)
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef ACCEL_TCG_INTERNAL_COMMON_H
#define ACCEL_TCG_INTERNAL_COMMON_H

#include "exec/cpu-common.h"
#include "exec/translation-block.h"
#include "exec/mmap-lock.h"
#include "accel/tcg/tb-cpu-state.h"
#include "hw/core/cpu.h"
#include "qemu/log.h"

extern int64_t max_delay;
extern int64_t max_advance;

extern bool one_insn_per_tb;

extern bool icount_align_option;

/*
 * Return true if CS is not running in parallel with other cpus, either
 * because there are no other cpus or we are within an exclusive context.
 */
static inline bool cpu_in_serial_context(CPUState *cs)
{
    return !tcg_cflags_has(cs, CF_PARALLEL) || cpu_in_exclusive_context(cs);
}

/**
 * cpu_plugin_mem_cbs_enabled() - are plugin memory callbacks enabled?
 * @cs: CPUState pointer
 *
 * The memory callbacks are installed if a plugin has instrumented an
 * instruction for memory. This can be useful to know if you want to
 * force a slow path for a series of memory accesses.
 */
static inline bool cpu_plugin_mem_cbs_enabled(const CPUState *cpu)
{
#ifdef CONFIG_PLUGIN
    return !!cpu->neg.plugin_mem_cbs;
#else
    return false;
#endif
}

TranslationBlock *tb_gen_code(CPUState *cpu, TCGTBCPUState s);
void page_init(void);
void tb_htable_init(void);
void tb_reset_jump(TranslationBlock *tb, int n);
TranslationBlock *tb_link_page(TranslationBlock *tb);
void cpu_restore_state_from_tb(CPUState *cpu, TranslationBlock *tb,
                               uintptr_t host_pc);

/**
 * tlb_init - initialize a CPU's TLB
 * @cpu: CPU whose TLB should be initialized
 */
void tlb_init(CPUState *cpu);
/**
 * tlb_destroy - destroy a CPU's TLB
 * @cpu: CPU whose TLB should be destroyed
 */
void tlb_destroy(CPUState *cpu);

/*
 * tlb_notdirty_redo - invalidate again what this thread's stores overlapped
 * @cpu: the CPU whose thread this is
 *
 * For the main loop, before a TB is looked up, when tlb_notdirty_redo_n says
 * that stores were made to pages with code since it last did: see
 * notdirty_write().
 */
extern __thread unsigned tlb_notdirty_redo_n;
void tlb_notdirty_redo(CPUState *cpu);

bool tcg_exec_realizefn(CPUState *cpu, Error **errp);
void tcg_exec_unrealizefn(CPUState *cpu);

/*
 * The log bits that make helper_lookup_tb_ptr() more than a lookup:
 * curr_cflags()'s, below, and its own log_cpu_exec().
 */
#define TB_LOOKUP_LOG_MASK \
    (CPU_LOG_TB_NOCHAIN | CPU_LOG_TB_CPU | CPU_LOG_EXEC)

/*
 * Current cflags for hashing/comparison. Inline, as helper_lookup_tb_ptr()
 * asks on every indirect branch the guest takes, where the call alone was
 * 3-4% of samples in CPython and in a configure script.
 *
 * TCTI's lookup_tb gadget copies these tests: see tcg_lookup_key, and keep
 * TB_LOOKUP_LOG_MASK in step.
 */
static inline uint32_t curr_cflags(CPUState *cpu)
{
    uint32_t cflags = cpu->tcg_cflags;

    /*
     * Record gdb single-step.  We should be exiting the TB by raising
     * EXCP_DEBUG, but to simplify other tests, disable chaining too.
     *
     * For singlestep and -d nochain, suppress goto_tb so that
     * we can log -d cpu,exec after every TB.
     */
    if (unlikely(cpu_single_stepping(cpu))) {
        cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR | CF_SINGLE_STEP | 1;
    } else if (qatomic_read(&one_insn_per_tb)) {
        cflags |= CF_NO_GOTO_TB | 1;
    } else if (qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        cflags |= CF_NO_GOTO_TB;
    }

    return cflags;
}

void tb_check_watchpoint(CPUState *cpu, uintptr_t retaddr);

/**
 * get_page_addr_code_hostp()
 * @env: CPUArchState
 * @addr: guest virtual address of guest code
 *
 * See get_page_addr_code() (full-system version) for documentation on the
 * return value.
 *
 * Sets *@hostp as follows.
 * If the return value is -1, sets *@hostp to NULL. Otherwise, sets *@hostp
 * to the host address where @addr's content is kept.
 *
 * Note: this function can trigger an exception.
 */
tb_page_addr_t get_page_addr_code_hostp(CPUArchState *env, vaddr addr,
                                        void **hostp);

/**
 * get_page_addr_code()
 * @env: CPUArchState
 * @addr: guest virtual address of guest code
 *
 * If we cannot translate and execute from the entire RAM page, or if
 * the region is not backed by RAM, returns -1. Otherwise, returns the
 * ram_addr_t corresponding to the guest code at @addr.
 *
 * Note: this function can trigger an exception.
 */
static inline tb_page_addr_t get_page_addr_code(CPUArchState *env,
                                                vaddr addr)
{
    void *discard;
    return get_page_addr_code_hostp(env, addr, &discard);
}

/*
 * Access to the various translations structures need to be serialised
 * via locks for consistency.  In user-mode emulation access to the
 * memory related structures are protected with mmap_lock.
 * In !user-mode we use per-page locks.
 */
#ifdef CONFIG_USER_ONLY
#define assert_memory_lock() tcg_debug_assert(have_mmap_lock())
#else
#define assert_memory_lock()
#endif

#if defined(CONFIG_SOFTMMU) && defined(CONFIG_DEBUG_TCG)
void assert_no_pages_locked(void);
#else
static inline void assert_no_pages_locked(void) { }
#endif

#ifdef CONFIG_USER_ONLY
static inline void page_table_config_init(void) { }
#else
void page_table_config_init(void);
#endif

#ifndef CONFIG_USER_ONLY
bool cpu_io_allowed(CPUState *cpu, uintptr_t retaddr);
G_NORETURN void cpu_io_recompile(CPUState *cpu, uintptr_t retaddr);
#endif /* CONFIG_USER_ONLY */

void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr);
void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr);

void tcg_get_stats(AccelState *accel, GString *buf);

#endif
