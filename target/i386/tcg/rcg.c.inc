/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RCG for x86: under TCTI, an instruction that rcg-gen.py has a gadget for
 * becomes one rich op in place of its TCG ops.
 *
 * disas_insn() offers each instruction here after decoding and every check,
 * exception and intercept, where TCG would start emitting its ops. What is
 * not taken goes to TCG, in the same TB.
 */

#if defined(TARGET_X86_64) && defined(TCG_HAVE_RCG)

#include "target/i386/trace.h"
#include "host/cpuinfo.h"
#include "tcti-gadget-defs.h"
#include "tcg/rcg-table.c.inc"

/* The gadgets' fast paths are built for TCTI's page size. */
QEMU_BUILD_BUG_ON(TARGET_PAGE_BITS != TCTI_TLB_PAGE_BITS);

/*
 * The instructions with gadgets, by decode-new's gen function: the op, and
 * which of decode->op[] are its first and second operands, the ones a
 * form's first two letters describe, destination first (-1 for none).
 * special is what decode-new's special must be if it is not
 * X86_SPECIAL_None, or -1 for anything.
 *
 * SUB and AND that write nothing are CMP and TEST, XOR of a register with
 * itself is the zero idiom, and MOV with ZExtT0 or SExtT0 is MOVZX, MOVSX
 * or MOVSXD: rcg_select() picks those. MOV to and from segment, control
 * and debug registers also uses gen_MOV, but rcg_kind() refuses those
 * operands.
 */
static const struct {
    X86GenFunc gen;
    RCGOp op;
    int8_t first, second;
    int8_t special;
} rcg_insns[] = {
    { gen_ADD,    RCG_OP_ADD,   1,  2, X86_SPECIAL_HasLock },
    { gen_SUB,    RCG_OP_SUB,   1,  2, X86_SPECIAL_HasLock },
    { gen_AND,    RCG_OP_AND,   1,  2, X86_SPECIAL_HasLock },
    { gen_OR,     RCG_OP_OR,    1,  2, X86_SPECIAL_HasLock },
    { gen_XOR,    RCG_OP_XOR,   1,  2, X86_SPECIAL_HasLock },
    /* ADC and SBB also read CF, which rcg_emit() puts in cc_src2. */
    { gen_ADC,    RCG_OP_ADC,   1,  2, X86_SPECIAL_HasLock },
    { gen_SBB,    RCG_OP_SBB,   1,  2, X86_SPECIAL_HasLock },
    { gen_MOV,    RCG_OP_MOV,   0,  1, X86_SPECIAL_None },
    { gen_LEA,    RCG_OP_LEA,   0,  1, X86_SPECIAL_NoLoadEA },
    { gen_PUSH,   RCG_OP_PUSH, -1,  1, -1 },
    { gen_POP,    RCG_OP_POP,   0, -1, -1 },
    { gen_NOT,    RCG_OP_NOT,   0, -1, X86_SPECIAL_HasLock },
    { gen_NEG,    RCG_OP_NEG,   0, -1, X86_SPECIAL_HasLock },
    /* The second operand of a shift or rotate is its count. */
    { gen_SHL,    RCG_OP_SHL,   0,  2, -1 },
    { gen_SHR,    RCG_OP_SHR,   0,  2, -1 },
    { gen_SAR,    RCG_OP_SAR,   0,  2, -1 },
    /* ROL runs as ROR by the width less the count; see rcg_emit(). */
    { gen_ROL,    RCG_OP_ROR,   0,  2, -1 },
    { gen_ROR,    RCG_OP_ROR,   0,  2, -1 },
    /*
     * MUL and IMUL with one operand multiply RAX by it; decode-new puts it
     * in op[1] and RAX in op[2]. With two or three, IMUL's third operand
     * is the destination again or an immediate; see rcg_operands().
     */
    { gen_MUL,    RCG_OP_MUL,  -1,  1, X86_SPECIAL_ZExtT0 },
    { gen_IMUL,   RCG_OP_IMUL, -1,  1, X86_SPECIAL_SExtT0 },
    { gen_IMUL3,  RCG_OP_IMUL3, 0,  1, X86_SPECIAL_SExtT0 },
    /*
     * The bit number is op[2]. BT writes nothing, so its operand is op[1];
     * BTS, BTR and BTC write op[0], and op[1] is the same operand.
     */
    { gen_BT,     RCG_OP_BT,    1,  2, -1 },
    { gen_BTS,    RCG_OP_BTS,   0,  2, -1 },
    { gen_BTR,    RCG_OP_BTR,   0,  2, -1 },
    { gen_BTC,    RCG_OP_BTC,   0,  2, -1 },
    { gen_CBW,    RCG_OP_CBW,   0, -1, -1 },
    { gen_CWD,    RCG_OP_CWD,   0,  1, -1 },
    /*
     * XCHG with memory is locked: decode-new sets PREFIX_LOCK, which
     * rcg_emit() refuses.
     */
    { gen_XCHG,   RCG_OP_XCHG,  0,  2, -1 },
    { gen_LEAVE,  RCG_OP_LEAVE, -1, -1, -1 },
    { gen_CALL,   RCG_OP_CALL, -1, -1, -1 },
    { gen_CALL_m, RCG_OP_CALL, -1,  1, -1 },
    { gen_JMP_m,  RCG_OP_JMP,  -1,  1, -1 },
    { gen_RET,    RCG_OP_RET,  -1, -1, -1 },
    /*
     * MOVDQU and MOVUPS; rcg_select() picks MOVDQA for those that must be
     * aligned.
     */
    { gen_MOVDQ,  RCG_OP_MOVDQU, 0,  2, -1 },
    /* MOVSD and MOVSS from memory, between registers, and to memory. */
    { gen_VMOVSD_ld,  RCG_OP_MOVSD, 0, 2, -1 },
    { gen_VMOVLPx,    RCG_OP_MOVSD, 0, 2, -1 },
    { gen_VMOVLPx_st, RCG_OP_MOVSD, 0, 2, -1 },
    { gen_VMOVSS_ld,  RCG_OP_MOVSS, 0, 2, -1 },
    { gen_VMOVSS,     RCG_OP_MOVSS, 0, 2, -1 },
    { gen_VMOVSS_st,  RCG_OP_MOVSS, 0, 2, -1 },
};

static bool sse_needs_alignment(DisasContext *s, X86DecodedInsn *decode,
                                MemOp ot);

/*
 * An operand's kind, as a form names it: register, memory, immediate or an
 * XMM register, or 0 if no form takes it.
 */
static char rcg_kind(DisasContext *s, X86DecodedOp *op)
{
    /* Check has_ea first: decode-new gives LEA's memory operand no unit. */
    if (op->has_ea) {
        return 'm';
    }
    switch (op->unit) {
    case X86_OP_INT:
        /* AH to BH too, though most ops refuse them; see rcg_is_xh(). */
        return 'r';
    case X86_OP_IMM:
        return 'i';
    case X86_OP_SSE:
        /*
         * rcg_operands() takes the width from the RCG op. A VEX encoding
         * may clear the upper half of the YMM, which no gadget does.
         */
        return s->prefix & PREFIX_VEX ? 0 : 'x';
    default:
        return 0;
    }
}

static int rcg_form(char a, char b)
{
    static const char *const names[RCG_NB_FORMS] = {
        [RCG_FORM_RR] = "rr", [RCG_FORM_RM] = "rm", [RCG_FORM_MR] = "mr",
        [RCG_FORM_RI] = "ri", [RCG_FORM_MI] = "mi", [RCG_FORM_R] = "r",
        [RCG_FORM_I] = "i", [RCG_FORM_M] = "m", [RCG_FORM_RRI] = "rri",
        [RCG_FORM_RMI] = "rmi", [RCG_FORM_XX] = "xx", [RCG_FORM_XM] = "xm",
        [RCG_FORM_MX] = "mx",
    };
    const char want[] = { a, b, 0 };

    for (int i = 0; i < RCG_NB_FORMS; i++) {
        if (!strcmp(names[i], want)) {
            return i;
        }
    }
    return -1;
}

/*
 * Returns the memory operand's shape, as gen_lea_modrm_1() forms the
 * address in 64-bit code. *seg is the segment whose base gen_lea_v_seg()
 * adds, which in 64-bit code is FS or GS only, else -1. Under CF_PCREL, a
 * RIP-relative address is env's eip plus a displacement, so it takes the
 * base-only shape.
 */
static RCGShape rcg_shape(DisasContext *s, X86DecodedInsn *decode, int *seg)
{
    AddressParts *a = &decode->mem;
    int ovr = s->override >= 0 ? s->override : a->def_seg;

    *seg = ovr >= R_FS ? ovr : -1;
    if (a->base == -2) {
        return tb_cflags(s->base.tb) & CF_PCREL ? RCG_EA_B : RCG_EA_D;
    }
    if (a->index >= 0) {
        return (a->base >= 0 ? RCG_EA_BI0 : RCG_EA_I0) + a->scale;
    }
    return a->base >= 0 ? RCG_EA_B : RCG_EA_D;
}

static uint64_t rcg_reg(int n)
{
    return offsetof(CPUX86State, regs[n]);
}

/*
 * Adds g to list unless it is already there. Each list has room for
 * RCG_MAX_WORDS.
 */
static void rcg_note_temp(TCGTemp **list, unsigned *n, TCGTemp *g)
{
    for (unsigned i = 0; i < *n; i++) {
        if (list[i] == g) {
            return;
        }
    }
    tcg_debug_assert(*n < RCG_MAX_WORDS);
    list[(*n)++] = g;
}

/* The same for v's temp. An XMM register has no global: v is NULL. */
static void rcg_note(TCGTemp **list, unsigned *n, TCGv v)
{
    if (v) {
        rcg_note_temp(list, n, tcgv_tl_temp(v));
    }
}

/*
 * Whether op is AH, CH, DH or BH. TCG reads these shifted down to bit 0
 * (gen_op_mov_v_reg()), but most gadgets work on the whole register, as
 * TCG does with the other registers, so their results would differ. A
 * gadget that uses only the low byte of an 8-bit register can take one as
 * the second byte of RAX to RBX (see rcg_reg_op()): those of the ops that
 * rcg_takes_xh() lists, and SETcc's.
 */
static bool rcg_is_xh(DisasContext *s, X86DecodedOp *op)
{
    return op->unit == X86_OP_INT && !op->has_ea && op->ot == MO_8 &&
           byte_reg_is_xH(s, op->n);
}

/* Whether op's gadgets take AH to BH; see rcg_is_xh(). */
static bool rcg_takes_xh(RCGOp op)
{
    switch (op) {
    case RCG_OP_MOV:
    case RCG_OP_MOVZXB:
    case RCG_OP_MOVSXB:
    case RCG_OP_XCHG:
    case RCG_OP_MUL:
    case RCG_OP_IMUL:
        return true;
    default:
        return false;
    }
}

/*
 * A register operand's env offset, as a gadget takes it, and *v, the
 * global it is in: AH to BH are the second byte of RAX to RBX. An XMM
 * register is in env alone, so *v is NULL.
 */
static uint64_t rcg_reg_op(DisasContext *s, X86DecodedOp *op, TCGv *v)
{
    if (op->unit == X86_OP_SSE) {
        *v = NULL;
        return offsetof(CPUX86State, xmm_regs[op->n]);
    }
    if (rcg_is_xh(s, op)) {
        *v = cpu_regs[op->n - 4];
        return rcg_reg(op->n - 4) + 1;
    }
    *v = cpu_regs[op->n];
    return rcg_reg(op->n);
}

/* The RCG_CC_* index of lazy-flags state cc_op, or -1 if no gadget reads it. */
static int rcg_cc_index(CCOp cc_op)
{
    if (cc_op >= CC_OP_SUBB && cc_op <= CC_OP_SUBQ) {
        return RCG_CC_SUB8 + (cc_op - CC_OP_SUBB);
    } else if (cc_op >= CC_OP_ADDB && cc_op <= CC_OP_ADDQ) {
        return RCG_CC_ADD8 + (cc_op - CC_OP_ADDB);
    } else if (cc_op >= CC_OP_LOGICB && cc_op <= CC_OP_LOGICQ) {
        return RCG_CC_LOGIC8 + (cc_op - CC_OP_LOGICB);
    } else if (cc_op >= CC_OP_INCB && cc_op <= CC_OP_INCQ) {
        return RCG_CC_INC8 + (cc_op - CC_OP_INCB);
    } else if (cc_op >= CC_OP_DECB && cc_op <= CC_OP_DECQ) {
        return RCG_CC_DEC8 + (cc_op - CC_OP_DECB);
    } else if (cc_op >= CC_OP_SARB && cc_op <= CC_OP_SARQ) {
        return RCG_CC_SAR8 + (cc_op - CC_OP_SARB);
    } else if (cc_op == CC_OP_EFLAGS) {
        return RCG_CC_EFLAGS;
    }
    return -1;
}

/*
 * The rich op of a CMP or TEST right before this instruction that a Jcc
 * can join, with *setter its index in rcg_fused_setter, or NULL. Only
 * set_cc_op()'s discards and CMP's update of cc_srcT may come between the
 * setter and the Jcc. Nothing reads what the discards drop before the
 * joined gadget writes it. This function removes the update: the Jcc does
 * not read cc_srcT, and it is dead once the Jcc ends the TB.
 */
static TCGOp *rcg_fused_setter_op(DisasContext *s, int *setter)
{
    TCGOp *op, *srct = NULL;
    const void *gadget;

    if (tcg_last_op() != s->base.insn_start) {
        return NULL;
    }
    for (op = QTAILQ_PREV(s->base.insn_start, link); op;
         op = QTAILQ_PREV(op, link)) {
        if (op->opc == INDEX_op_add && !srct &&
            arg_temp(op->args[0]) == tcgv_tl_temp(s->cc_srcT)) {
            srct = op;
        } else if (op->opc != INDEX_op_discard) {
            break;
        }
    }
    gadget = tcg_rich_gadget(op);
    for (int i = 0; gadget && i < RCG_NB_FUSED; i++) {
        if (rcg_fused_setter[i] == gadget) {
            if (srct) {
                tcg_op_remove(tcg_ctx, srct);
            }
            *setter = i;
            return op;
        }
    }
    return NULL;
}

/*
 * Jcc, SETcc and CMOVcc, when an earlier instruction in this TB left a
 * lazy-flags state the gadgets read. Returns the gadget emitted, or NULL.
 */
static const void *rcg_translate_cond(DisasContext *s,
                                      X86DecodedInsn *decode)
{
    X86GenFunc gen = decode->e.gen;
    int cc = rcg_cc_index(s->cc_op), cond = decode->b & 0xf;
    TCGTemp *flags_in[2] = {
        tcgv_tl_temp(cpu_cc_dst), tcgv_tl_temp(cpu_cc_src)
    };

    if (cc < 0) {
        return NULL;
    }
    if (gen == gen_Jcc) {
        const void *gadget = rcg_jcc[cc][cond];
        TCGTemp *out = tcgv_i32_temp(cpu_cc_op);
        uint64_t word = s->cc_op;
        TCGLabel *taken;
        TCGOp *setter_op;
        int setter;

        if (!gadget) {
            return NULL;
        }
        /*
         * As gen_Jcc, but the gadget always stores CC_OP, even where it is
         * already clean (after COMISS, FCOMI or PUSHF, for example). Right
         * after a CMP or TEST of registers or an immediate, one gadget
         * does both, branching on the values it compared rather than
         * reloading cc_dst and cc_src.
         */
        taken = gen_new_label();
        gen_bnd_jmp(s);
        setter_op = rcg_fused_setter_op(s, &setter);
        if (setter_op) {
            gadget = rcg_fjcc[setter][cond];
            tcg_gen_rich_br_join(setter_op, gadget, &word, 1, taken,
                                 rcg_fjccgoto[setter][cond], &out, 1,
                                 NULL, 0);
        } else {
            tcg_gen_rich_br(gadget, &word, 1, taken, rcg_jccgoto[cc][cond],
                            &out, 1, flags_in, 2);
        }
        s->cc_op_dirty = false;
        gen_conditional_jump_labels(s, decode->immediate, NULL, taken);
        return gadget;
    }
    if (gen == gen_SETcc) {
        X86DecodedOp *d = &decode->op[0];
        const void *gadget = rcg_setcc[cc][cond];
        uint64_t word;
        TCGTemp *out, *ins[3] = { flags_in[0], flags_in[1] };
        TCGv reg;

        if (!gadget || rcg_kind(s, d) != 'r') {
            return NULL;
        }
        word = rcg_reg_op(s, d, &reg);
        /* It writes the low byte, so it reads the rest of the register. */
        out = ins[2] = tcgv_tl_temp(reg);
        tcg_gen_rich(gadget, &word, 1, 0, &out, 1, ins, 3);
        return gadget;
    }
    if (gen == gen_CMOVcc) {
        X86DecodedOp *d = &decode->op[0], *src = &decode->op[2];
        const void *gadget;
        uint64_t words[2];
        TCGTemp *out, *ins[4] = { flags_in[0], flags_in[1] };
        unsigned nb_ins = 2;

        if (d->ot < MO_16 || d->ot > MO_64 || rcg_kind(s, d) != 'r' ||
            rcg_kind(s, src) != 'r') {
            return NULL;
        }
        gadget = rcg_cmov[d->ot][cc][cond];
        if (!gadget) {
            return NULL;
        }
        words[0] = rcg_reg(d->n);
        words[1] = rcg_reg(src->n);
        /* Without the move, it keeps the destination. */
        out = ins[nb_ins++] = tcgv_tl_temp(cpu_regs[d->n]);
        if (src->n != d->n) {
            ins[nb_ins++] = tcgv_tl_temp(cpu_regs[src->n]);
        }
        tcg_gen_rich(gadget, words, 2, 0, &out, 1, ins, nb_ins);
        return gadget;
    }
    return NULL;
}

/*
 * After the gadget has rotated register n (width ot) right by count, sets
 * CF and OF as gen_ROL and gen_ROR do and keeps the other flags. Those
 * leave CC_OP_ADCOX; this leaves CC_OP_EFLAGS, with every flag in cc_src.
 * These ops are removed as dead if the flags are set again before anything
 * reads them.
 */
static void rcg_rotate_flags(DisasContext *s, MemOp ot, int n, bool left,
                             int count)
{
    TCGv res = tcg_temp_new(), old = tcg_temp_new();
    TCGv flags = tcg_temp_new(), bit = tcg_temp_new();
    int top = (8 << ot) - 1;

    gen_mov_eflags(s, flags);
    if (ot == MO_32) {
        TCGv_i32 t = tcg_temp_new_i32();

        tcg_gen_trunc_tl_i32(t, cpu_regs[n]);
        tcg_gen_extu_i32_tl(res, t);
        tcg_gen_rotli_i32(t, t, count);
        tcg_gen_extu_i32_tl(old, t);
    } else {
        tcg_gen_mov_tl(res, cpu_regs[n]);
        tcg_gen_rotli_tl(old, res, count);
    }
    /* CF: the bit that went round. OF: whether the top bit changed. */
    tcg_gen_extract_tl(bit, res, left ? 0 : top, 1);
    tcg_gen_deposit_tl(flags, flags, bit, ctz32(CC_C), 1);
    tcg_gen_xor_tl(bit, old, res);
    tcg_gen_extract_tl(bit, bit, top, 1);
    tcg_gen_deposit_tl(flags, flags, bit, ctz32(CC_O), 1);
    tcg_gen_mov_tl(cpu_cc_src, flags);
    set_cc_op(s, CC_OP_EFLAGS);
}

/*
 * The op for decode's instruction, and its first and second operands as
 * rcg_insns[] describes them; or false if RCG has no op for it.
 */
static bool rcg_select(DisasContext *s, X86DecodedInsn *decode, RCGOp *op,
                       X86DecodedOp **first, X86DecodedOp **second)
{
    X86GenFunc gen = decode->e.gen;
    bool writes = decode->op[0].unit != X86_OP_SKIP;
    int i;

    if (gen == gen_MOV && (decode->e.special == X86_SPECIAL_ZExtT0 ||
                           decode->e.special == X86_SPECIAL_SExtT0)) {
        /* MOVZX, MOVSX and MOVSXD, by the source's size. */
        bool sext = decode->e.special == X86_SPECIAL_SExtT0;

        /* MOV to a control or debug register is ZExtT0 too. */
        if (decode->op[0].unit != X86_OP_INT) {
            return false;
        }
        *first = &decode->op[0];
        *second = &decode->op[1];
        switch ((*second)->ot) {
        case MO_8:
            *op = sext ? RCG_OP_MOVSXB : RCG_OP_MOVZXB;
            return true;
        case MO_16:
            *op = sext ? RCG_OP_MOVSXW : RCG_OP_MOVZXW;
            return true;
        case MO_32:
            *op = RCG_OP_MOVSXD;
            return sext;
        default:
            return false;
        }
    }

    for (i = 0; i < ARRAY_SIZE(rcg_insns); i++) {
        if (rcg_insns[i].gen == gen) {
            break;
        }
    }
    if (i == ARRAY_SIZE(rcg_insns) ||
        (rcg_insns[i].special >= 0 &&
         decode->e.special != X86_SPECIAL_None &&
         decode->e.special != rcg_insns[i].special)) {
        return false;
    }
    *op = rcg_insns[i].op;
    *first = rcg_insns[i].first >= 0 ? &decode->op[rcg_insns[i].first] : NULL;
    *second = rcg_insns[i].second >= 0 ? &decode->op[rcg_insns[i].second]
                                       : NULL;

    if (*op == RCG_OP_MOVDQU &&
        sse_needs_alignment(s, decode, decode->op[0].ot)) {
        *op = RCG_OP_MOVDQA;
    } else if (*op == RCG_OP_SUB && !writes) {
        *op = RCG_OP_CMP;
    } else if (*op == RCG_OP_AND && !writes) {
        *op = RCG_OP_TEST;
    } else if (*op == RCG_OP_XOR && (*first)->unit == X86_OP_INT &&
               (*second)->unit == X86_OP_INT && !(*first)->has_ea &&
               !(*second)->has_ea && (*first)->n == (*second)->n) {
        /* A register XORed with itself, as gen_XOR special-cases. */
        *op = RCG_OP_ZERO;
    }
    return true;
}

/*
 * The form of op's instruction, its operand width and any immediate; or -1
 * if RCG leaves it to TCG. *rotate_left says that a ROR is ROL's.
 */
static int rcg_operands(DisasContext *s, X86DecodedInsn *decode, RCGOp op,
                        X86DecodedOp *first, X86DecodedOp *second,
                        MemOp *ot, uint64_t *imm, bool *rotate_left)
{
    switch (rcg_facts[op].kind) {
    case RCG_KIND_CALL:
    case RCG_KIND_JMP:
    case RCG_KIND_RET:
        /*
         * CALL's gadget pushes env's eip plus s->pc - s->pc_save, which is
         * the return address only under CF_PCREL, where cpu_eip tracks
         * pc_save. System mode always has CF_PCREL; JMP and RET are kept
         * to it too.
         */
        if (!(tb_cflags(s->base.tb) & CF_PCREL)) {
            return -1;
        }
        if (op == RCG_OP_RET) {
            /* An unsigned count, as gen_RET takes it. */
            uint16_t adjust = decode->e.op1 == X86_TYPE_I ? decode->immediate
                                                          : 0;
            *imm = adjust + 8;
        } else if (op == RCG_OP_CALL) {
            *imm = s->pc - s->pc_save;
        }
        /* Only a 64-bit return address and target. */
        *ot = op == RCG_OP_JMP ? second->ot : mo_pushpop(s, s->dflag);
        if (*ot != MO_64) {
            return -1;
        }
        return second ? rcg_form(rcg_kind(s, second), 0) : RCG_FORM_I;
    case RCG_KIND_PUSH:
    case RCG_KIND_POP: {
        X86DecodedOp *o = first ? first : second;
        int form;

        *ot = mo_pushpop(s, s->dflag);
        if (*ot != MO_64) {
            return -1;
        }
        form = rcg_form(rcg_kind(s, o), 0);
        if (form == RCG_FORM_I) {
            *imm = o->imm;
        }
        return form;
    }
    case RCG_KIND_UNARY:
        *ot = first->ot;
        return rcg_form(rcg_kind(s, first), 0);
    case RCG_KIND_MUL:
        *ot = second->ot;
        return rcg_form(rcg_kind(s, second), 0);
    case RCG_KIND_CBW:
        *ot = first->ot;
        return rcg_form(rcg_kind(s, first), 0);
    case RCG_KIND_VMOV: {
        /*
         * A 16-byte gadget with memory needs LSE2 to make its access
         * single-copy atomic, as TCTI's qemu_ld_i128 and qemu_st_i128
         * gadgets do.
         */
        char a = rcg_kind(s, first), b = rcg_kind(s, second);

        *ot = op == RCG_OP_MOVSD ? MO_64 : op == RCG_OP_MOVSS ? MO_32 : MO_128;
        if (!a || !b || (*ot == MO_128 && (a == 'm' || b == 'm') &&
                         !(cpuinfo & CPUINFO_LSE2))) {
            return -1;
        }
        return rcg_form(a, b);
    }
    case RCG_KIND_LEAVE:
        /* Only a 64-bit RBP. */
        *ot = mo_pushpop(s, s->dflag);
        return *ot == MO_64 ? RCG_FORM_R : -1;
    case RCG_KIND_BT: {
        char a = rcg_kind(s, first), b = rcg_kind(s, second);

        /*
         * After CC_OP_DYNAMIC or a state with EFLAGS in cc_src, TCG
         * computes the flags in full; see gen_bt_flags(). With the bit
         * number in a register, a memory operand is a bit string that can
         * reach beyond the operand, so that is left to TCG too.
         */
        *ot = first->ot;
        if (s->cc_op == CC_OP_DYNAMIC || CC_OP_HAS_EFLAGS(s->cc_op) ||
            !a || !b || (a == 'm' && b == 'r')) {
            return -1;
        }
        if (b == 'i') {
            *imm = second->imm & ((8 << *ot) - 1);
        }
        return rcg_form(a, b);
    }
    case RCG_KIND_IMUL3: {
        char a = rcg_kind(s, first), b = rcg_kind(s, second);

        *ot = first->ot;
        if (a != 'r' || !b) {
            return -1;
        }
        if (decode->op[2].unit != X86_OP_IMM) {
            return rcg_form(a, b);
        }
        *imm = decode->op[2].imm;
        return b == 'r' ? RCG_FORM_RRI : RCG_FORM_RMI;
    }
    case RCG_KIND_SHIFT: {
        /*
         * By an immediate count, or 1, or CL. An immediate that masks to 0
         * is left to TCG, which then keeps the flags but still writes the
         * operand back, zero-extending a 32-bit register; a gadget by CL
         * does the same for a count of 0 itself. ROL and ROR by CL are left
         * to TCG.
         */
        char a = rcg_kind(s, first);

        *ot = first->ot;
        if (second->unit == X86_OP_INT) {
            return a && op != RCG_OP_ROR ? rcg_form(a, 'r') : -1;
        } else if (second->unit == X86_OP_IMM) {
            *imm = second->imm & (*ot <= MO_32 ? 0x1f : 0x3f);
        } else if (second->unit == X86_OP_SKIP) {
            *imm = 1;
        } else {
            return -1;
        }
        if (!*imm) {
            return -1;
        }
        if (op == RCG_OP_ROR) {
            /*
             * ROL and ROR of a 32- or 64-bit register. ROL by n is ROR by
             * the width less n. At these widths, x86's count mask keeps the
             * count below the width.
             */
            if (*ot < MO_32 || a != 'r') {
                return -1;
            }
            *rotate_left = decode->e.gen == gen_ROL;
            if (*rotate_left) {
                *imm = (8 << *ot) - *imm;
            }
        }
        return a ? rcg_form(a, 'i') : -1;
    }
    default: {
        /*
         * Two operands of the same width, unless the second is an
         * immediate, LEA's address or an extend's source.
         */
        char a = rcg_kind(s, first), b = rcg_kind(s, second);

        *ot = first->ot;
        if (!a || !b || *ot > MO_64 ||
            (b != 'i' && op != RCG_OP_LEA && rcg_facts[op].src_ot < 0 &&
             second->ot != *ot)) {
            return -1;
        }
        if (b == 'i') {
            *imm = second->imm;
        }
        return rcg_form(a, b);
    }
    }
}

/*
 * Emits the gadget for decode's instruction, if there is one, and returns
 * it, or NULL.
 */
static const void *rcg_emit(DisasContext *s, X86DecodedInsn *decode)
{
    X86DecodedOp *first, *second;
    X86GenFunc gen = decode->e.gen;
    MemOp ot, memop = 0;
    RCGOp op;
    const RCGFacts *facts;
    uint64_t imm = 0;
    int form, shape = 0, seg = -1;
    bool ordered = false, rotate_left = false, by_cl, carry;
    const RCGSlot *slot;
    const RCGGadget *g;
    uint64_t words[RCG_MAX_WORDS];
    TCGTemp *outs[RCG_MAX_WORDS], *ins[RCG_MAX_WORDS];
    unsigned n, nb_outs = 0, nb_ins = 0;
    TCGv reg;

    if (!CODE64(s) || (s->prefix & PREFIX_LOCK)) {
        return NULL;
    }
    /*
     * In 64-bit code the address size changes only how a memory operand's
     * address is formed. The stack address is always 64-bit
     * (mo_stacksize()), and RCG has no gadget for the instructions that
     * use registers at the address size: string instructions, XLAT, LOOP
     * and JRCXZ.
     */
    if (s->aflag != MO_64 && (decode->op[0].has_ea || decode->op[1].has_ea ||
                              decode->op[2].has_ea)) {
        return NULL;
    }
    if (gen == gen_Jcc || gen == gen_SETcc || gen == gen_CMOVcc) {
        return rcg_translate_cond(s, decode);
    }
    if (!rcg_select(s, decode, &op, &first, &second)) {
        return NULL;
    }
    facts = &rcg_facts[op];

    form = rcg_operands(s, decode, op, first, second, &ot, &imm,
                        &rotate_left);
    if (form < 0) {
        return NULL;
    }
    if (((first && rcg_is_xh(s, first)) || (second && rcg_is_xh(s, second))) &&
        !rcg_takes_xh(op)) {
        return NULL;
    }
    /* A shift by CL leaves a flags state only the gadget knows. */
    by_cl = facts->kind == RCG_KIND_SHIFT && second->unit == X86_OP_INT;
    slot = &rcg_slots[op][form];
    if (!slot->gadgets) {
        return NULL;
    }

    /*
     * The gadget for the width, the address's shape and whether a segment
     * base is added. Each gadget's ordered twin follows it.
     */
    if (slot->nb_shapes > 1) {
        shape = rcg_shape(s, decode, &seg);
        if (op == RCG_OP_LEA) {
            /* gen_LEA adds no segment base. */
            seg = -1;
        }
    }
    g = &slot->gadgets[((ot * slot->nb_shapes + shape) * 2 + (seg >= 0)) * 2];
    /*
     * Check before emitting a barrier, so an instruction left to TCG gets
     * none. A gadget that accesses memory always has an ordered twin, so
     * checking this one is enough.
     */
    if (!g->gadget) {
        return NULL;
    }
    carry = op == RCG_OP_ADC || op == RCG_OP_SBB;
    if (carry) {
        /*
         * gen_ADC and gen_SBB leave another flags state for an immediate
         * of 0 (CC_OP_ADD or CC_OP_SUB) and for SBB of a register with
         * itself (CC_OP_SBB_SELF), so those cases stay with TCG.
         *
         * CF is written to cc_src2 before the gadget runs. A fault in the
         * gadget restores the flags state from before the instruction, and
         * if that state uses cc_src2, its value would already be lost. So
         * a gadget that accesses memory is refused after such a state.
         */
        if (((form == RCG_FORM_RI || form == RCG_FORM_MI) && !imm) ||
            (op == RCG_OP_SBB && form == RCG_FORM_RR &&
             first->n == second->n) ||
            (slot->access && (cc_op_live(s->cc_op) & USES_CC_SRC2))) {
            return NULL;
        }
    }
    if (slot->access) {
        /*
         * The barriers gen_op_ld_v() and gen_op_st_v() would emit before
         * the accesses. PUSH m's store depends on its load; CALL m's
         * gadget, which stores the return address after loading the
         * target, orders the two itself.
         */
        TCGBar bar = 0;

        bar |= slot->access & RCG_LOAD ? TCG_MO_LD_LD | TCG_MO_ST_LD : 0;
        bar |= slot->access & RCG_STORE ? TCG_MO_LD_ST | TCG_MO_ST_ST : 0;
        ordered = tcg_gen_rich_mo(bar);
        memop = (facts->src_ot >= 0 ? facts->src_ot : ot) | MO_LE;
        if (facts->kind == RCG_KIND_VMOV && ot == MO_128) {
            /* As gen_ldo_env_A0() and gen_sto_env_A0() make it. */
            memop |= (s->cpuid_ext_features & CPUID_EXT_AVX
                      ? MO_ATOM_IFALIGN : MO_ATOM_IFALIGN_PAIR) |
                     (op == RCG_OP_MOVDQA ? MO_ALIGN_16 : 0);
        }
    }
    g += ordered;
    tcg_debug_assert(g->gadget);

    /*
     * The globals it writes, and those it reads besides its words' (below).
     * A register it writes at 8 or 16 bits keeps the rest, so it reads it.
     */
    if (facts->stack) {
        rcg_note(outs, &nb_outs, cpu_regs[R_ESP]);
        rcg_note(ins, &nb_ins, cpu_regs[R_ESP]);
    }
    if (op == RCG_OP_CALL) {
        /* For the return address. CALL rel's jump is gen_JMP's, after. */
        rcg_note(ins, &nb_ins, cpu_eip);
    }
    if (facts->kind == RCG_KIND_MUL) {
        /*
         * It reads RAX, and writes it and, above 8 bits, RDX. DX at 16 bits
         * keeps the rest of RDX.
         */
        rcg_note(outs, &nb_outs, cpu_regs[R_EAX]);
        rcg_note(ins, &nb_ins, cpu_regs[R_EAX]);
        if (ot > MO_8) {
            rcg_note(outs, &nb_outs, cpu_regs[R_EDX]);
        }
        if (ot == MO_16) {
            rcg_note(ins, &nb_ins, cpu_regs[R_EDX]);
        }
    }
    if (facts->branch && !(op == RCG_OP_CALL && form == RCG_FORM_I)) {
        rcg_note(outs, &nb_outs, cpu_eip);
    }
    for (n = 0; n < RCG_MAX_WORDS && g->words[n] != RCG_W_END; n++) {
        if (g->words[n] == RCG_W_D) {
            rcg_reg_op(s, first, &reg);
            rcg_note(outs, &nb_outs, reg);
            if (slot->reads_d || ot < MO_32) {
                rcg_note(ins, &nb_ins, reg);
            }
        }
    }
    if (op == RCG_OP_XCHG) {
        /* It writes its source too. */
        rcg_reg_op(s, second, &reg);
        rcg_note(outs, &nb_outs, reg);
    }
    if (op == RCG_OP_LEAVE) {
        rcg_note(outs, &nb_outs, cpu_regs[R_EBP]);
        rcg_note(ins, &nb_ins, cpu_regs[R_EBP]);
    }
    if (facts->dst) {
        rcg_note(outs, &nb_outs, cpu_cc_dst);
    }
    if (facts->src) {
        rcg_note(outs, &nb_outs, cpu_cc_src);
    }
    if (by_cl) {
        /* With a count of 0 it keeps the flags state, cc_op included. */
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_cc_op));
        rcg_note(ins, &nb_ins, cpu_cc_dst);
        rcg_note(ins, &nb_ins, cpu_cc_src);
        rcg_note_temp(ins, &nb_ins, tcgv_i32_temp(cpu_cc_op));
    }

    /* The words, in the order the gadget takes them, and what it reads. */
    for (n = 0; n < RCG_MAX_WORDS && g->words[n] != RCG_W_END; n++) {
        AddressParts *a = &decode->mem;

        switch (g->words[n]) {
        case RCG_W_D:
            words[n] = rcg_reg_op(s, first, &reg);
            break;
        case RCG_W_S1:
            words[n] = rcg_reg_op(s, first, &reg);
            rcg_note(ins, &nb_ins, reg);
            break;
        case RCG_W_S:
            words[n] = rcg_reg_op(s, second, &reg);
            rcg_note(ins, &nb_ins, reg);
            break;
        case RCG_W_BASE:
            if (a->base == -2) {
                words[n] = offsetof(CPUX86State, eip);
                rcg_note(ins, &nb_ins, cpu_eip);
            } else {
                words[n] = rcg_reg(a->base);
                rcg_note(ins, &nb_ins, cpu_regs[a->base]);
            }
            break;
        case RCG_W_INDEX:
            words[n] = rcg_reg(a->index);
            rcg_note(ins, &nb_ins, cpu_regs[a->index]);
            break;
        case RCG_W_DISP:
            /*
             * Under CF_PCREL a RIP-relative address is cpu_eip, the eip at
             * pc_save, plus disp - pc_save, as gen_lea_modrm_1() computes.
             */
            words[n] = a->disp;
            if (a->base == -2 && shape == RCG_EA_B) {
                words[n] -= s->pc_save;
            }
            break;
        case RCG_W_SEG:
            words[n] = offsetof(CPUX86State, segs[seg].base);
            rcg_note(ins, &nb_ins, cpu_seg_base[seg]);
            break;
        case RCG_W_IMM:
            words[n] = imm;
            break;
        case RCG_W_OI:
            words[n] = make_memop_idx(memop, s->mem_index);
            break;
        case RCG_W_TLB:
            words[n] = TCTI_TLB_FAST_OFS(s->mem_index);
            break;
        case RCG_W_CCOP:
            /* The state before, which a shift by CL keeps for a count of 0. */
            words[n] = s->cc_op;
            break;
        default:
            g_assert_not_reached();
        }
    }
    if (carry) {
        /* CF, from the state before the instruction, goes in cc_src2. */
        TCGv cf = tcg_temp_new();

        gen_compute_eflags_c(s, cf);
        tcg_gen_mov_tl(cpu_cc_src2, cf);
        rcg_note(ins, &nb_ins, cpu_cc_src2);
    }
    tcg_gen_rich(g->gadget, words, n, slot->access ? TCG_RICH_MAY_FAULT : 0,
                 outs, nb_outs, ins, nb_ins);

    if (op == RCG_OP_ROR) {
        rcg_rotate_flags(s, ot, first->n, rotate_left, imm);
    }

    /*
     * CALL rel ends with gen_JMP, as gen_CALL does. The other branches have
     * set eip, and end the TB as gen_CALL_m, gen_JMP_m and gen_RET do.
     */
    if (op == RCG_OP_CALL && form == RCG_FORM_I) {
        gen_JMP(s, decode);
    } else if (facts->branch) {
        s->pc_save = -1;
        gen_bnd_jmp(s);
        s->base.is_jmp = DISAS_JUMP;
    }

    /*
     * Record the lazy-flags state the gadget left. After a shift by CL it
     * is in env, which the gadget wrote.
     */
    if (by_cl) {
        assume_cc_op(s, CC_OP_DYNAMIC);
    } else if (facts->kind == RCG_KIND_BT) {
        /* cc_dst is kept, so the width is the earlier state's. */
        set_cc_op(s, CC_OP_SARB + cc_op_size(s->cc_op));
    } else if (facts->cc_op >= 0) {
        set_cc_op(s, facts->cc_op + (facts->by_width ? ot : 0));
        if (facts->srcT == RCG_SRCT_SUM) {
            tcg_gen_add_tl(s->cc_srcT, cpu_cc_dst, cpu_cc_src);
        } else if (facts->srcT == RCG_SRCT_ZERO) {
            tcg_gen_movi_tl(s->cc_srcT, 0);
        }
    }
    return g->gadget;
}

/*
 * Emits one gadget for decode's instruction if RCG has one, and returns
 * whether it did. The trace events say which instructions it took, by
 * gadget, and which it left to TCG, by decode-new's gen function.
 */
static bool rcg_translate(DisasContext *s, X86DecodedInsn *decode)
{
    const void *gadget;

    /*
     * Plugins instrument memory accesses through qemu_ld and qemu_st ops,
     * which a gadget bypasses.
     */
    if (!tcg_rcg_active() || s->base.plugin_enabled) {
        return false;
    }
    gadget = rcg_emit(s, decode);
    if (gadget) {
        trace_rcg_insn(s->base.pc_next, gadget);
    } else {
        trace_rcg_insn_declined(s->base.pc_next, (void *)decode->e.gen);
    }
    return gadget != NULL;
}

#else

static bool rcg_translate(DisasContext *s, X86DecodedInsn *decode)
{
    return false;
}

#endif
