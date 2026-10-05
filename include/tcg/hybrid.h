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

/*
 * Map, and under TXM prepare, the code buffer for TCTI or native code, ahead
 * of a switch to it; from any thread. 1 if done now, 2 if already, 0 if it
 * could not be. The __locked form is for a switch, which holds the lock from
 * preparing to the buffer being in use. See region.c.
 */
void tcg_region_hybrid_lock(void);
void tcg_region_hybrid_unlock(void);
int tcg_region_hybrid_prepare(bool tcti, Error **errp);
int tcg_region_hybrid_prepare__locked(bool tcti, Error **errp);

/* Give the native backend's buffer back while TCTI is in use. See region.c. */
bool tcg_region_hybrid_release_native(Error **errp);
bool tcg_region_hybrid_native_ready(void);

/* Switch to TCTI or to native code; from safe work. See tcg.c. */
bool tcg_hybrid_switch(bool tcti, Error **errp);
#elif defined(CONFIG_TCG_THREADED_INTERPRETER)
#define tcg_tcti_active()  true
#else
#define tcg_tcti_active()  false
#endif

#endif /* TCG_HYBRID_H */
