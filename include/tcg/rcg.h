/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * RCG, the rich code generator: under TCTI, a guest instruction the front
 * end has a gadget for runs as that one gadget rather than as a gadget for
 * each of its TCG ops. Only x86-64 guests have gadgets. It is off by
 * default; -accel tcg,rcg=on|off sets it at startup, and tctish_rcg_set()
 * or the monitor's tcg_rcg while the VM runs. It is never active while
 * native code runs (the hybrid's JIT), as the gadgets exist only for TCTI's
 * streams.
 *
 * tcg_rcg_active() is a constant false in builds that cannot run TCTI, so
 * a test of it costs nothing there.
 */

#ifndef TCG_RCG_H
#define TCG_RCG_H

#include "tcg/hybrid.h"

#ifdef TCG_HAVE_TCTI
#define TCG_HAVE_RCG 1

/* Set at startup, then only by tctish_rcg_set() while no vCPU translates. */
extern bool tcg_rcg_enabled;

/*
 * Whether to translate with RCG. Turning RCG on or off and switching the
 * hybrid's backend change it only while no vCPU is translating, and every
 * TB translated with the old answer is then discarded. Test it only while
 * translating, and never keep the answer past the TB.
 */
#define tcg_rcg_active()  (tcg_rcg_enabled && tcg_tcti_active())
#else
#define tcg_rcg_active()  false
#endif

#endif /* TCG_RCG_H */
