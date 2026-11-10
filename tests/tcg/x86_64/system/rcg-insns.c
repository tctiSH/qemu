/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Every instruction form RCG has a gadget for, over awkward values.
 *
 * RCG runs an x86 instruction under TCTI as one gadget, where TCG runs a
 * TCG op at a time; it must give exactly what TCG gives. The cases come from
 * the tables in target/i386/tcg/rcg-gen.py that RCG's gadgets are made from
 * (see rcg-test.h), with the neighbors of each form that are left to TCG.
 * Each runs over every pair of values from rcg_values (or each single
 * value, where the form takes one operand), from every start in
 * rcg_starts (those marked fp only for the cases with floating-point
 * values). The registers, the arithmetic flags, SETcc's result for each
 * condition, XMM0 to XMM3 for a case that uses them, MXCSR for one with
 * floating-point values, and the memory the case can reach are hashed, and
 * a case prints its hash.
 *
 * rcg-insns.ref holds TCG's hashes. To regenerate it after rcg-gen.py
 * changes the cases, run the test under TCG (in a build with TCTI, with
 * -accel tcg,rcg=off) and copy the output over it.
 */

#include "rcg-test.h"
#ifndef RCG_INSN_CASES
#define RCG_INSN_CASES "rcg-insns.h"
#endif
#include RCG_INSN_CASES

#define NB_CASES (sizeof(rcg_insn_cases) / sizeof(rcg_insn_cases[0]))

bool rcg_exception(struct rcg_frame *f)
{
    return false;
}

static uint64_t run(const struct rcg_case *c)
{
    int nx = c->a >= 0 ? RCG_NB_VALUES : 1;
    int ny = c->b >= 0 || c->mem || c->stack ? RCG_NB_VALUES : 1;
    uint64_t h = RCG_HASH_INIT;

    for (int s = 0; s < RCG_NB_STARTS; s++) {
        if (rcg_starts[s].fp && c->xmm < RCG_XMM_F64) {
            continue;
        }
        for (int x = 0; x < nx; x++) {
            for (int y = 0; y < ny; y++) {
                uint64_t flags;

                rcg_setup(c, rcg_values[x], rcg_values[y], &rcg_starts[s]);
                rcg_run(c, &rcg_starts[s]);
                flags = rcg_out.flags & RCG_FLAGS;
                h = rcg_hash(h, rcg_out.r, sizeof(rcg_out.r));
                h = rcg_hash(h, &flags, sizeof(flags));
                h = rcg_hash(h, rcg_out.cc, sizeof(rcg_out.cc));
                if (c->xmm) {
                    h = rcg_hash(h, rcg_out.x, sizeof(rcg_out.x));
                }
                if (c->xmm >= RCG_XMM_F64) {
                    h = rcg_hash(h, &rcg_out.mxcsr, sizeof(rcg_out.mxcsr));
                }
                h = rcg_hash(h, rcg_bytes(RCG_MEM), RCG_MEM_SIZE);
                h = rcg_hash(h, rcg_bytes(RCG_STACK - RCG_STACK_SIZE),
                             2 * RCG_STACK_SIZE);
            }
        }
    }
    return h;
}

int main(void)
{
    rcg_init();
    for (int i = 0; i < NB_CASES; i++) {
        ml_printf("%s: %lx\n", rcg_insn_cases[i].name, run(&rcg_insn_cases[i]));
    }
    return 0;
}
