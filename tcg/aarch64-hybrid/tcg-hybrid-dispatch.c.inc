/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The AArch64 hybrid's backend interface when the backend is chosen at
 * startup: each function tcg.c calls, and the ones tcg-target-protos.h.inc
 * declares, passing to the active backend's renamed copy.
 *
 * Generated from tcg-target-protos.h.inc; regenerate it with that.
 */

static void tcg_target_init(TCGContext *s)
{
    if (tcg_tcti_active()) {
        tcti_tcg_target_init(s);
    } else {
        aa64_tcg_target_init(s);
    }
}

static void tcg_target_qemu_prologue(TCGContext *s)
{
    if (tcg_tcti_active()) {
        tcti_tcg_target_qemu_prologue(s);
    } else {
        aa64_tcg_target_qemu_prologue(s);
    }
}

static bool patch_reloc(tcg_insn_unit *code_ptr,
                        int type,
                        intptr_t value,
                        intptr_t addend)
{
    if (tcg_tcti_active()) {
        return tcti_patch_reloc(code_ptr, type, value, addend);
    } else {
        return aa64_patch_reloc(code_ptr, type, value, addend);
    }
}

static void tcg_out_nop_fill(tcg_insn_unit *p, int count)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_nop_fill(p, count);
    } else {
        aa64_tcg_out_nop_fill(p, count);
    }
}

static bool tcg_out_qemu_ld_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    if (tcg_tcti_active()) {
        return tcti_tcg_out_qemu_ld_slow_path(s, l);
    } else {
        return aa64_tcg_out_qemu_ld_slow_path(s, l);
    }
}

static bool tcg_out_qemu_st_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    if (tcg_tcti_active()) {
        return tcti_tcg_out_qemu_st_slow_path(s, l);
    } else {
        return aa64_tcg_out_qemu_st_slow_path(s, l);
    }
}

static void tcg_out_tb_start(TCGContext *s)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_tb_start(s);
    } else {
        aa64_tcg_out_tb_start(s);
    }
}

static void tcg_out_ld(TCGContext *s,
                       TCGType type,
                       TCGReg ret,
                       TCGReg arg1,
                       intptr_t arg2)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_ld(s, type, ret, arg1, arg2);
    } else {
        aa64_tcg_out_ld(s, type, ret, arg1, arg2);
    }
}

static bool tcg_out_mov(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        return tcti_tcg_out_mov(s, type, ret, arg);
    } else {
        return aa64_tcg_out_mov(s, type, ret, arg);
    }
}

static void tcg_out_movi(TCGContext *s,
                         TCGType type,
                         TCGReg ret,
                         tcg_target_long arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_movi(s, type, ret, arg);
    } else {
        aa64_tcg_out_movi(s, type, ret, arg);
    }
}

static void tcg_out_ext8s(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_ext8s(s, type, ret, arg);
    } else {
        aa64_tcg_out_ext8s(s, type, ret, arg);
    }
}

static void tcg_out_ext16s(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_ext16s(s, type, ret, arg);
    } else {
        aa64_tcg_out_ext16s(s, type, ret, arg);
    }
}

static void tcg_out_ext8u(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_ext8u(s, ret, arg);
    } else {
        aa64_tcg_out_ext8u(s, ret, arg);
    }
}

static void tcg_out_ext16u(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_ext16u(s, ret, arg);
    } else {
        aa64_tcg_out_ext16u(s, ret, arg);
    }
}

static void tcg_out_ext32s(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_ext32s(s, ret, arg);
    } else {
        aa64_tcg_out_ext32s(s, ret, arg);
    }
}

static void tcg_out_ext32u(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_ext32u(s, ret, arg);
    } else {
        aa64_tcg_out_ext32u(s, ret, arg);
    }
}

static void tcg_out_exts_i32_i64(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_exts_i32_i64(s, ret, arg);
    } else {
        aa64_tcg_out_exts_i32_i64(s, ret, arg);
    }
}

static void tcg_out_extu_i32_i64(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_extu_i32_i64(s, ret, arg);
    } else {
        aa64_tcg_out_extu_i32_i64(s, ret, arg);
    }
}

static void tcg_out_extrl_i64_i32(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_extrl_i64_i32(s, ret, arg);
    } else {
        aa64_tcg_out_extrl_i64_i32(s, ret, arg);
    }
}

static void tcg_out_addi_ptr(TCGContext *s,
                             TCGReg a1,
                             TCGReg a2,
                             tcg_target_long a3)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_addi_ptr(s, a1, a2, a3);
    } else {
        aa64_tcg_out_addi_ptr(s, a1, a2, a3);
    }
}

static bool tcg_out_xchg(TCGContext *s, TCGType type, TCGReg r1, TCGReg r2)
{
    if (tcg_tcti_active()) {
        return tcti_tcg_out_xchg(s, type, r1, r2);
    } else {
        return aa64_tcg_out_xchg(s, type, r1, r2);
    }
}

static void tcg_out_exit_tb(TCGContext *s, uintptr_t arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_exit_tb(s, arg);
    } else {
        aa64_tcg_out_exit_tb(s, arg);
    }
}

static void tcg_out_goto_tb(TCGContext *s, int which)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_goto_tb(s, which);
    } else {
        aa64_tcg_out_goto_tb(s, which);
    }
}

static void tcg_out_goto_ptr(TCGContext *s, TCGReg dest)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_goto_ptr(s, dest);
    } else {
        aa64_tcg_out_goto_ptr(s, dest);
    }
}

static void tcg_out_mb(TCGContext *s, unsigned bar)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_mb(s, bar);
    } else {
        aa64_tcg_out_mb(s, bar);
    }
}

static void tcg_out_br(TCGContext *s, TCGLabel *l)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_br(s, l);
    } else {
        aa64_tcg_out_br(s, l);
    }
}

static void tcg_out_set_carry(TCGContext *s)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_set_carry(s);
    } else {
        aa64_tcg_out_set_carry(s);
    }
}

static void tcg_out_set_borrow(TCGContext *s)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_set_borrow(s);
    } else {
        aa64_tcg_out_set_borrow(s);
    }
}

static bool tcg_out_dup_vec(TCGContext *s,
                            TCGType type,
                            unsigned vece,
                            TCGReg dst,
                            TCGReg src)
{
    if (tcg_tcti_active()) {
        return tcti_tcg_out_dup_vec(s, type, vece, dst, src);
    } else {
        return aa64_tcg_out_dup_vec(s, type, vece, dst, src);
    }
}

static bool tcg_out_dupm_vec(TCGContext *s,
                             TCGType type,
                             unsigned vece,
                             TCGReg dst,
                             TCGReg base,
                             intptr_t offset)
{
    if (tcg_tcti_active()) {
        return tcti_tcg_out_dupm_vec(s, type, vece, dst, base, offset);
    } else {
        return aa64_tcg_out_dupm_vec(s, type, vece, dst, base, offset);
    }
}

static void tcg_out_dupi_vec(TCGContext *s,
                             TCGType type,
                             unsigned vece,
                             TCGReg dst,
                             int64_t arg)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_dupi_vec(s, type, vece, dst, arg);
    } else {
        aa64_tcg_out_dupi_vec(s, type, vece, dst, arg);
    }
}

static void tcg_out_vec_op(TCGContext *s,
                           TCGOpcode opc,
                           unsigned vecl,
                           unsigned vece,
                           const TCGArg args[TCG_MAX_OP_ARGS],
                           const int const_args[TCG_MAX_OP_ARGS])
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_vec_op(s, opc, vecl, vece, args, const_args);
    } else {
        aa64_tcg_out_vec_op(s, opc, vecl, vece, args, const_args);
    }
}

static void tcg_out_st(TCGContext *s,
                       TCGType type,
                       TCGReg arg,
                       TCGReg arg1,
                       intptr_t arg2)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_st(s, type, arg, arg1, arg2);
    } else {
        aa64_tcg_out_st(s, type, arg, arg1, arg2);
    }
}

static bool tcg_out_sti(TCGContext *s,
                        TCGType type,
                        TCGArg val,
                        TCGReg base,
                        intptr_t ofs)
{
    if (tcg_tcti_active()) {
        return tcti_tcg_out_sti(s, type, val, base, ofs);
    } else {
        return aa64_tcg_out_sti(s, type, val, base, ofs);
    }
}

static void tcg_out_call(TCGContext *s,
                         const tcg_insn_unit *target,
                         const TCGHelperInfo *info)
{
    if (tcg_tcti_active()) {
        tcti_tcg_out_call(s, target, info);
    } else {
        aa64_tcg_out_call(s, target, info);
    }
}

static TCGReg tcg_target_call_oarg_reg(TCGCallReturnKind kind, int slot)
{
    if (tcg_tcti_active()) {
        return tcti_tcg_target_call_oarg_reg(kind, slot);
    } else {
        return aa64_tcg_target_call_oarg_reg(kind, slot);
    }
}

static bool tcg_target_const_match(int64_t val,
                                   int ct,
                                   TCGType type,
                                   TCGCond cond,
                                   int vece)
{
    if (tcg_tcti_active()) {
        return tcti_tcg_target_const_match(val, ct, type, cond, vece);
    } else {
        return aa64_tcg_target_const_match(val, ct, type, cond, vece);
    }
}

/* Declared in tcg.c itself, with the constraint machinery. */
static TCGConstraintSetIndex tcg_target_op_def(TCGOpcode op, TCGType type,
                                               unsigned flags)
{
    return tcg_tcti_active() ? tcti_tcg_target_op_def(op, type, flags)
                             : aa64_tcg_target_op_def(op, type, flags);
}

/* The backends' external interface, likewise. */

void tb_target_set_jmp_target(const TranslationBlock *tb, int n,
                              uintptr_t jmp_rx, uintptr_t jmp_rw)
{
    if (tcg_tcti_active()) {
        tcti_tb_target_set_jmp_target(tb, n, jmp_rx, jmp_rw);
    } else {
        aa64_tb_target_set_jmp_target(tb, n, jmp_rx, jmp_rw);
    }
}

int tcg_can_emit_vec_op(TCGOpcode opc, TCGType type, unsigned vece)
{
    return tcg_tcti_active() ? tcti_tcg_can_emit_vec_op(opc, type, vece)
                             : aa64_tcg_can_emit_vec_op(opc, type, vece);
}

bool tcg_target_has_memory_bswap(MemOp memop)
{
    return tcg_tcti_active() ? tcti_tcg_target_has_memory_bswap(memop)
                             : aa64_tcg_target_has_memory_bswap(memop);
}

/*
 * Both backends read exactly two arguments past a0, whatever the opcode, so
 * those two are all there is to pass on.
 */
void tcg_expand_vec_op(TCGOpcode opc, TCGType type, unsigned vece,
                       TCGArg a0, ...)
{
    va_list va;
    TCGArg a1, a2;

    va_start(va, a0);
    a1 = va_arg(va, TCGArg);
    a2 = va_arg(va, TCGArg);
    va_end(va);

    if (tcg_tcti_active()) {
        tcti_tcg_expand_vec_op(opc, type, vece, a0, a1, a2);
    } else {
        aa64_tcg_expand_vec_op(opc, type, vece, a0, a1, a2);
    }
}

/* Only native code is described to a debugger. */
void tcg_register_jit(const void *buf, size_t buf_size)
{
    if (!tcg_tcti_active()) {
        aa64_tcg_register_jit(buf, buf_size);
    }
}
