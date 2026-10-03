/* SPDX-License-Identifier: MIT */
/*
 * Forward declarations for the functions a tcg-target.c.inc defines: those
 * tcg.c calls, and those the backend calls before it defines them.
 *
 * Apart from tcg.c, so that a backend built from others can declare these
 * once for each of them, under the names it compiles that one with.
 */

static void tcg_target_init(TCGContext *s);
static void tcg_target_qemu_prologue(TCGContext *s);
static bool patch_reloc(tcg_insn_unit *code_ptr, int type,
                        intptr_t value, intptr_t addend);
static void tcg_out_nop_fill(tcg_insn_unit *p, int count);

static bool tcg_out_qemu_ld_slow_path(TCGContext *s, TCGLabelQemuLdst *l);
static bool tcg_out_qemu_st_slow_path(TCGContext *s, TCGLabelQemuLdst *l);

static void tcg_out_tb_start(TCGContext *s);
static void tcg_out_ld(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg1,
                       intptr_t arg2);
static bool tcg_out_mov(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg);
static void tcg_out_movi(TCGContext *s, TCGType type,
                         TCGReg ret, tcg_target_long arg);
static void tcg_out_ext8s(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg);
static void tcg_out_ext16s(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg);
static void tcg_out_ext8u(TCGContext *s, TCGReg ret, TCGReg arg);
static void tcg_out_ext16u(TCGContext *s, TCGReg ret, TCGReg arg);
static void tcg_out_ext32s(TCGContext *s, TCGReg ret, TCGReg arg);
static void tcg_out_ext32u(TCGContext *s, TCGReg ret, TCGReg arg);
static void tcg_out_exts_i32_i64(TCGContext *s, TCGReg ret, TCGReg arg);
static void tcg_out_extu_i32_i64(TCGContext *s, TCGReg ret, TCGReg arg);
static void tcg_out_extrl_i64_i32(TCGContext *s, TCGReg ret, TCGReg arg);
static void tcg_out_addi_ptr(TCGContext *s, TCGReg, TCGReg, tcg_target_long);
static bool tcg_out_xchg(TCGContext *s, TCGType type, TCGReg r1, TCGReg r2);
static void tcg_out_exit_tb(TCGContext *s, uintptr_t arg);
static void tcg_out_goto_tb(TCGContext *s, int which);
static void tcg_out_goto_ptr(TCGContext *s, TCGReg dest);
static void tcg_out_mb(TCGContext *s, unsigned bar);
static void tcg_out_br(TCGContext *s, TCGLabel *l);
static void tcg_out_set_carry(TCGContext *s);
static void tcg_out_set_borrow(TCGContext *s);
#if TCG_TARGET_MAYBE_vec
static bool tcg_out_dup_vec(TCGContext *s, TCGType type, unsigned vece,
                            TCGReg dst, TCGReg src);
static bool tcg_out_dupm_vec(TCGContext *s, TCGType type, unsigned vece,
                             TCGReg dst, TCGReg base, intptr_t offset);
static void tcg_out_dupi_vec(TCGContext *s, TCGType type, unsigned vece,
                             TCGReg dst, int64_t arg);
static void tcg_out_vec_op(TCGContext *s, TCGOpcode opc,
                           unsigned vecl, unsigned vece,
                           const TCGArg args[TCG_MAX_OP_ARGS],
                           const int const_args[TCG_MAX_OP_ARGS]);
#endif
static void tcg_out_st(TCGContext *s, TCGType type, TCGReg arg, TCGReg arg1,
                       intptr_t arg2);
static bool tcg_out_sti(TCGContext *s, TCGType type, TCGArg val,
                        TCGReg base, intptr_t ofs);
static void tcg_out_call(TCGContext *s, const tcg_insn_unit *target,
                         const TCGHelperInfo *info);
static TCGReg tcg_target_call_oarg_reg(TCGCallReturnKind kind, int slot);
static bool tcg_target_const_match(int64_t val, int ct,
                                   TCGType type, TCGCond cond, int vece);
