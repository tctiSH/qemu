/*
 * Get host pc for helper unwinding.
 *
 * Copyright (c) 2003 Fabrice Bellard
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef ACCEL_TCG_GETPC_H
#define ACCEL_TCG_GETPC_H

#ifndef CONFIG_TCG
#error Can only include this header with TCG
#endif

/* GETPC is the true target of the return instruction that we'll execute.  */
#if defined(CONFIG_TCG_INTERPRETER)
extern __thread uintptr_t tci_tb_ptr;
# define GETPC() tci_tb_ptr
#elif defined(CONFIG_TCG_THREADED_INTERPRETER)
/* Set by TCTI's call gadget: the gadget stream position of the call. */
extern __thread uintptr_t tcti_call_return_address;
# define GETPC() tcti_call_return_address
#elif defined(CONFIG_TCG_HYBRID_RUNTIME)
/* The hybrid: TCTI's, or the return address, as the active backend has it. */
extern bool tcg_hybrid_tcti;
extern __thread uintptr_t tcti_call_return_address;
# define GETPC() \
    (tcg_hybrid_tcti ? tcti_call_return_address : \
     (uintptr_t)__builtin_extract_return_addr(__builtin_return_address(0)))
#else
# define GETPC() \
    ((uintptr_t)__builtin_extract_return_addr(__builtin_return_address(0)))
#endif

#endif /* ACCEL_TCG_GETPC_H */
