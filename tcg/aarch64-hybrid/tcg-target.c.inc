/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The AArch64 hybrid: the aarch64 backend and TCTI, compiled into one tcg.c.
 *
 * Each backend's tcg-target.c.inc is included as it stands. The active one
 * keeps its names, so tcg.c calls it exactly as it would on its own; the
 * other is compiled under tcg-hybrid-rename.h's prefixed names, beside it.
 * Which is active is fixed when QEMU is configured, for now: TCTI where
 * CONFIG_TCG_THREADED_INTERPRETER is defined, as it is for a TCTI build, and
 * aarch64 otherwise.
 *
 * Between the two, what each backend's own header would have defined
 * differently: the env and frame registers, and aarch64's ELF_HOST_MACHINE,
 * which turns on tcg.c's GDB JIT interface. What is left defined afterwards
 * is the active backend's, for tcg.c.
 */

#ifdef CONFIG_TCG_THREADED_INTERPRETER
#define TCG_HYBRID_INACTIVE_AA64  1
#define TCG_HYBRID_INACTIVE_TCTI  0
#else
#define TCG_HYBRID_INACTIVE_AA64  0
#define TCG_HYBRID_INACTIVE_TCTI  1
#endif

/*
 * The inactive backend's code is all there but nothing reaches it, so its
 * static functions and data would each be warned about.
 */
#define TCG_HYBRID_QUIET_BEGIN                                          \
    _Pragma("GCC diagnostic push")                                      \
    _Pragma("GCC diagnostic ignored \"-Wunused-function\"")             \
    _Pragma("GCC diagnostic ignored \"-Wunused-variable\"")             \
    _Pragma("GCC diagnostic ignored \"-Wunused-const-variable\"")
#define TCG_HYBRID_QUIET_END  _Pragma("GCC diagnostic pop")

/* aarch64. */

#define TCG_AREG0  TCG_REG_X19

#if TCG_HYBRID_INACTIVE_AA64
#define TCG_HYBRID_PREFIX  aa64
#include "tcg-hybrid-rename.h"
#include "../tcg-target-protos.h.inc"
TCG_HYBRID_QUIET_BEGIN
#endif

#include "../aarch64/tcg-target.c.inc"

#if TCG_HYBRID_INACTIVE_AA64
TCG_HYBRID_QUIET_END
#include "tcg-hybrid-unrename.h"
#undef TCG_HYBRID_PREFIX
#undef ELF_HOST_MACHINE
#endif

#undef TCG_AREG0
#undef TCG_REG_CALL_STACK   /* aarch64's tcg-target.c.inc defines it */

/* TCTI. */

#define TCG_AREG0           TCG_REG_R14
#define TCG_REG_CALL_STACK  TCG_REG_R15

#if TCG_HYBRID_INACTIVE_TCTI
#define TCG_HYBRID_PREFIX  tcti
#include "tcg-hybrid-rename.h"
#include "../tcg-target-protos.h.inc"
TCG_HYBRID_QUIET_BEGIN
#endif

#include "../aarch64-tcti/tcg-target.c.inc"

#if TCG_HYBRID_INACTIVE_TCTI
TCG_HYBRID_QUIET_END
#include "tcg-hybrid-unrename.h"
#undef TCG_HYBRID_PREFIX

/* aarch64 is the active one, so its registers again. */
#undef TCG_AREG0
#undef TCG_REG_CALL_STACK
#define TCG_AREG0           TCG_REG_X19
#define TCG_REG_CALL_STACK  TCG_REG_SP
#endif

#undef TCG_HYBRID_INACTIVE_AA64
#undef TCG_HYBRID_INACTIVE_TCTI
#undef TCG_HYBRID_QUIET_BEGIN
#undef TCG_HYBRID_QUIET_END
