/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The AArch64 hybrid: the aarch64 backend and TCTI, compiled into one tcg.c.
 *
 * Each backend's tcg-target.c.inc is included as it stands, in one of two
 * ways. Where the backend is fixed when QEMU is configured (tcti or jit), the
 * active one keeps its names, so tcg.c calls it exactly as it would on its
 * own, and the other is compiled under tcg-hybrid-rename.h's prefixed names
 * beside it. Where it is chosen at startup (runtime), both are renamed, and
 * tcg-hybrid-dispatch.c.inc defines tcg.c's interface over them.
 *
 * Between the two, what each backend's own header would have defined
 * differently: the env and frame registers, and aarch64's ELF_HOST_MACHINE,
 * which turns on tcg.c's GDB JIT interface. What is left defined afterwards
 * is the active backend's, for tcg.c.
 */

#if defined(CONFIG_TCG_HYBRID_RUNTIME)
#define TCG_HYBRID_RENAME_AA64  1
#define TCG_HYBRID_RENAME_TCTI  1
#elif defined(CONFIG_TCG_THREADED_INTERPRETER)
#define TCG_HYBRID_RENAME_AA64  1
#define TCG_HYBRID_RENAME_TCTI  0
#else
#define TCG_HYBRID_RENAME_AA64  0
#define TCG_HYBRID_RENAME_TCTI  1
#endif

/*
 * A renamed backend's code is all there, but parts of it are not reached --
 * all of it, where the other is fixed as the active one -- so its static
 * functions and data would each be warned about.
 */
#define TCG_HYBRID_QUIET_BEGIN                                          \
    _Pragma("GCC diagnostic push")                                      \
    _Pragma("GCC diagnostic ignored \"-Wunused-function\"")             \
    _Pragma("GCC diagnostic ignored \"-Wunused-variable\"")             \
    _Pragma("GCC diagnostic ignored \"-Wunused-const-variable\"")
#define TCG_HYBRID_QUIET_END  _Pragma("GCC diagnostic pop")

/* aarch64. */

#define TCG_AREG0  TCG_REG_X19

#if TCG_HYBRID_RENAME_AA64
#define TCG_HYBRID_PREFIX  aa64
#include "tcg-hybrid-rename.h"
#include "../tcg-target-protos.h.inc"
TCG_HYBRID_QUIET_BEGIN
#endif

#include "../aarch64/tcg-target.c.inc"

#if TCG_HYBRID_RENAME_AA64
TCG_HYBRID_QUIET_END
#include "tcg-hybrid-unrename.h"
#undef TCG_HYBRID_PREFIX
#endif
#if TCG_HYBRID_RENAME_AA64 && !defined(CONFIG_TCG_HYBRID_RUNTIME)
#undef ELF_HOST_MACHINE   /* aarch64 is never active */
#endif

#undef TCG_AREG0
#undef TCG_REG_CALL_STACK   /* aarch64's tcg-target.c.inc defines it */

/* TCTI. */

#define TCG_AREG0           TCG_REG_R14
#define TCG_REG_CALL_STACK  TCG_REG_R15

#if TCG_HYBRID_RENAME_TCTI
#define TCG_HYBRID_PREFIX  tcti
#include "tcg-hybrid-rename.h"
#include "../tcg-target-protos.h.inc"
TCG_HYBRID_QUIET_BEGIN
#endif

#include "../aarch64-tcti/tcg-target.c.inc"

#if TCG_HYBRID_RENAME_TCTI
TCG_HYBRID_QUIET_END
#include "tcg-hybrid-unrename.h"
#undef TCG_HYBRID_PREFIX
#endif

/* What tcg.c is left with. */

#if defined(CONFIG_TCG_HYBRID_RUNTIME)
#undef TCG_AREG0
#undef TCG_REG_CALL_STACK
#define TCG_AREG0           (tcg_tcti_active() ? TCG_REG_R14 : TCG_REG_X19)
#define TCG_REG_CALL_STACK  (tcg_tcti_active() ? TCG_REG_R15 : TCG_REG_SP)

#include "tcg-hybrid-dispatch.c.inc"

/* The same registers, x0-x7 and R0-R7, in both. */
#define tcg_target_call_iarg_regs  aa64_tcg_target_call_iarg_regs
#define tcg_target_reg_names \
    (tcg_tcti_active() ? tcti_tcg_target_reg_names : aa64_tcg_target_reg_names)
#define tcg_target_reg_alloc_order \
    (tcg_tcti_active() ? tcti_tcg_target_reg_alloc_order \
                       : aa64_tcg_target_reg_alloc_order)
#define TCG_TARGET_REG_ALLOC_ORDER_COUNT \
    (tcg_tcti_active() ? ARRAY_SIZE(tcti_tcg_target_reg_alloc_order) \
                       : ARRAY_SIZE(aa64_tcg_target_reg_alloc_order))
#define TCG_TARGET_REG_ALLOC_ORDER_MAX \
    MAX_CONST(ARRAY_SIZE(tcti_tcg_target_reg_alloc_order), \
        ARRAY_SIZE(aa64_tcg_target_reg_alloc_order))

/* The two outop tables tcg.c builds; see TCG_TARGET_OUTOPS. */
#define TCG_HYBRID_OUTOP_AA64(O, T, V)  OUTOP(O, T, aa64_##V)
#define TCG_HYBRID_OUTOP_TCTI(O, T, V)  OUTOP(O, T, tcti_##V)

#elif TCG_HYBRID_RENAME_TCTI
/* aarch64 is the active one, so its registers again. */
#undef TCG_AREG0
#undef TCG_REG_CALL_STACK
#define TCG_AREG0           TCG_REG_X19
#define TCG_REG_CALL_STACK  TCG_REG_SP
#endif

#undef TCG_HYBRID_RENAME_AA64
#undef TCG_HYBRID_RENAME_TCTI
#undef TCG_HYBRID_QUIET_BEGIN
#undef TCG_HYBRID_QUIET_END
