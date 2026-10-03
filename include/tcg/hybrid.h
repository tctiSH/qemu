/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Which backend generates code, for code outside it that must know.
 *
 * TCTI, the threaded-dispatch interpreter, writes gadget streams that are
 * data; the native backend writes code the host executes. A build has one
 * or the other, except the AArch64 hybrid configured with
 * --enable-tcg-hybrid=runtime, which has both and picks one at startup
 * (-accel tcg,tcti=on|off).
 *
 * tcg_tcti_active() is a constant everywhere but there, so a test of it
 * costs nothing in any other build.
 */

#ifndef TCG_HYBRID_H
#define TCG_HYBRID_H

#if defined(CONFIG_TCG_HYBRID_RUNTIME)
extern bool tcg_hybrid_tcti;
#define tcg_tcti_active()  (tcg_hybrid_tcti)
#elif defined(CONFIG_TCG_THREADED_INTERPRETER)
#define tcg_tcti_active()  true
#else
#define tcg_tcti_active()  false
#endif

#endif /* TCG_HYBRID_H */
