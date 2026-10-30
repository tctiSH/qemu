/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * rcg-insns' Jcc cases again, which the Makefile runs under -d nochain.
 *
 * TCTI swaps a jumps gadget in for a Jcc whose ways both end in a goto_tb,
 * which all of rcg-insns' cases that jump forward do, so that test does not
 * show what the plain Jcc gadgets do. A loop that is one TB runs those.
 * Without goto_tb, the same cases run them, each way. Their hashes are the
 * ones in rcg-insns.ref.
 */

#define RCG_INSN_CASES "rcg-jcc.h"
#include "rcg-insns.c"
