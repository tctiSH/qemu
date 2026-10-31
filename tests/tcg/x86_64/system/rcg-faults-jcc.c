/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * rcg-faults' Jcc cases again, which the Makefile runs under -d nochain.
 *
 * rcg-faults' joined CMP and TEST may fault in the jumps gadgets TCTI swaps
 * in. Without goto_tb, the same cases fault in the plain ones.
 */

#define RCG_FAULT_CASES "rcg-faults-jcc.h"
#include "rcg-faults.c"
