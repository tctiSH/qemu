/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Float helpers whose fast path a backend may emit in place of the call.
 *
 * A target registers the helpers that compute a lane-wise float operation
 * on vectors in env, called as helper(env, d, v, s) with d, v and s
 * pointers: d = v op s. For a scalar one, lane 0 of the 16 bytes is v op s
 * and the other lanes are v's. min gives v < s ? v : s, max v > s ? v : s.
 *
 * A backend meeting a call to one may emit the operation itself, and must
 * fall back to the call unless every condition below holds, so that the
 * result, and the exception flags in float_status, are exactly the
 * helper's (TCG_INLINE_FP conditions):
 *
 *  - For add, sub, mul and div: (word at status_ofs & status_mask) ==
 *    status_want, which is round-to-nearest-even, no flush to zero of
 *    inputs or outputs, and the inexact flag already raised, so that the
 *    operation cannot raise it anew.
 *  - Every lane of v, s and the result is zero or a normal finite number:
 *    then nothing but inexact can be raised, and the host computes the same
 *    value in round-to-nearest.
 *  - For mul and div, no lane's result is zero unless v's is (and for mul,
 *    s's may be): a zero from nonzero operands is an underflow.
 *
 * min and max round nothing and raise nothing under the lane condition, so
 * they need no status check.
 */

#ifndef TCG_INLINE_FP_H
#define TCG_INLINE_FP_H

#include "exec/memop.h"

typedef enum TCGInlineFPOp {
    TCG_INLINE_FP_ADD,
    TCG_INLINE_FP_SUB,
    TCG_INLINE_FP_MUL,
    TCG_INLINE_FP_DIV,
    TCG_INLINE_FP_MIN,
    TCG_INLINE_FP_MAX,
} TCGInlineFPOp;

typedef struct TCGInlineFP {
    TCGInlineFPOp op;
    MemOp esize;            /* MO_32 or MO_64 */
    unsigned bytes;         /* 16 or 32 for a packed op; 0 for a scalar one */
    intptr_t status_ofs;    /* from env, the 32-bit word of float_status... */
    uint32_t status_mask;   /* ...these bits of which... */
    uint32_t status_want;   /* ...must equal these */
} TCGInlineFP;

/*
 * Registers `helper`. `float_status_ofs` is the offset from env of the
 * float_status the helper uses. Only before any translation.
 */
void tcg_register_inline_fp(const void *helper, TCGInlineFPOp op, MemOp esize,
                            unsigned bytes, intptr_t float_status_ofs);

/* The registration for `helper`, or NULL. */
const TCGInlineFP *tcg_inline_fp(const void *helper);

#endif /* TCG_INLINE_FP_H */
