/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Float helpers whose fast path a backend may emit in place of the call;
 * see tcg/tcg-inline-fp.h.
 */

#include "qemu/osdep.h"
#include "tcg/tcg-inline-fp.h"
#include "fpu/softfloat-types.h"
#include "fpu/softfloat.h"

static GHashTable *inline_fps;

/* The first 32 bits of a float_status, which hold its flags and modes. */
static uint32_t status_word(const float_status *s)
{
    uint32_t word;

    memcpy(&word, s, sizeof(word));
    return word;
}

void tcg_register_inline_fp(const void *helper, TCGInlineFPOp op, MemOp esize,
                            unsigned bytes, intptr_t float_status_ofs)
{
    TCGInlineFP *fp = g_new0(TCGInlineFP, 1);
    float_status zero, t;
    uint32_t mask = 0, want;

    QEMU_BUILD_BUG_ON(sizeof(float_status) < sizeof(uint32_t));
    QEMU_BUILD_BUG_ON(TCG_INLINE_FP_NEG_C != float_muladd_negate_c);
    QEMU_BUILD_BUG_ON(TCG_INLINE_FP_NEG_PRODUCT !=
                      float_muladd_negate_product);
    QEMU_BUILD_BUG_ON(float_round_nearest_even != 0);

    /*
     * Which bits of the word hold what is up to the compiler's bitfield
     * layout, so find out rather than assume: set each field alone and see
     * what changes. Round-to-nearest-even and the flush controls are all
     * zeros; inexact is the one bit wanted set.
     */
    memset(&zero, 0, sizeof(zero));
    t = zero;
    t.float_rounding_mode = 7;
    mask |= status_word(&t) ^ status_word(&zero);
    t = zero;
    t.flush_to_zero = true;
    mask |= status_word(&t) ^ status_word(&zero);
    t = zero;
    t.flush_inputs_to_zero = true;
    mask |= status_word(&t) ^ status_word(&zero);
    t = zero;
    t.float_exception_flags = float_flag_inexact;
    want = status_word(&t) ^ status_word(&zero);
    mask |= want;
    g_assert(want && mask != want);

    fp->op = op;
    fp->esize = esize;
    fp->bytes = bytes;
    fp->status_ofs = float_status_ofs;
    fp->status_mask = mask;
    fp->status_want = want;

    if (!inline_fps) {
        inline_fps = g_hash_table_new(NULL, NULL);
    }
    g_hash_table_insert(inline_fps, (gpointer)helper, fp);
}

const TCGInlineFP *tcg_inline_fp(const void *helper)
{
    return inline_fps ? g_hash_table_lookup(inline_fps, helper) : NULL;
}
