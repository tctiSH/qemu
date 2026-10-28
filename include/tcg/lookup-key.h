/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * helper_lookup_tb_ptr()'s common case, as data, for a back end that looks
 * up the next TB itself: TCTI's lookup_tb gadget.
 */

#ifndef TCG_LOOKUP_KEY_H
#define TCG_LOOKUP_KEY_H

/*
 * Where a lookup reads env. The target's fields say how its
 * get_tb_cpu_state() makes the state in its common case: flags is the
 * 32-bit word at flags_ofs ORed with the 32-bit word at extra_ofs ANDed
 * with extra_mask, pc the 64-bit word at pc_ofs and cs_base 0, while flags
 * has a bit of mode set. pc_ofs is 0 until a target sets them.
 *
 * accel/tcg's fields are CPUState's, relative to env, and what makes
 * curr_cflags() more than tcg_cflags or makes check_for_breakpoints() look:
 * a back end that finds single-stepping, a breakpoint, one_insn_per_tb or
 * a log bit of log_mask calls the helper.
 *
 * Each field is 64 bits, so that a gadget loads them in pairs.
 */
typedef struct TCGLookupKey {
    int64_t flags_ofs, extra_ofs;
    uint64_t extra_mask, mode;
    int64_t pc_ofs;

    int64_t cflags_ofs, jc_ofs;
    int64_t sstep_ofs, bp_ofs;
    int64_t io_ofs;
    const bool *one_insn_per_tb;
    const unsigned *loglevel;
    uint64_t log_mask;
} TCGLookupKey;

extern TCGLookupKey tcg_lookup_key;

/*
 * The jump cache's shape, which accel/tcg checks against its own: 2 to the
 * TCG_LOOKUP_JC_BITS entries of a TB and a pc, 16 bytes each, after an
 * rcu_head; and the guest page size the softmmu hash assumes, which a back
 * end must check.
 */
#define TCG_LOOKUP_JC_BITS      14
#define TCG_LOOKUP_JC_ARRAY_OFS 16
#define TCG_LOOKUP_PAGE_BITS    12

#endif /* TCG_LOOKUP_KEY_H */
