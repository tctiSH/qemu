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
#include "tcti-gadget-defs.h"
#include "tcg/rcg-table.c.inc"

/* The gadgets' fast paths are built for TCTI's page size. */
QEMU_BUILD_BUG_ON(TARGET_PAGE_BITS != TCTI_TLB_PAGE_BITS);

/*
 * The instructions with gadgets, by decode-new's gen function: the op, and
 * which of decode->op[] are its first and second operands, the ones a
 * form's two letters describe, destination first (-1 for none). special is
 * what decode-new's special must be if it is not X86_SPECIAL_None, or -1
 * for anything.
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
    { gen_MOV,    RCG_OP_MOV,   0,  1, X86_SPECIAL_None },
    { gen_LEA,    RCG_OP_LEA,   0,  1, X86_SPECIAL_NoLoadEA },
    { gen_PUSH,   RCG_OP_PUSH, -1,  1, -1 },
    { gen_POP,    RCG_OP_POP,   0, -1, -1 },
    { gen_NOT,    RCG_OP_NOT,   0, -1, X86_SPECIAL_HasLock },
    { gen_NEG,    RCG_OP_NEG,   0, -1, X86_SPECIAL_HasLock },
    { gen_INC,    RCG_OP_INC,   0, -1, X86_SPECIAL_HasLock },
    { gen_DEC,    RCG_OP_DEC,   0, -1, X86_SPECIAL_HasLock },
    /* The second operand of a shift or rotate is its count. */
    { gen_SHL,    RCG_OP_SHL,   0,  2, -1 },
    { gen_SHR,    RCG_OP_SHR,   0,  2, -1 },
    { gen_SAR,    RCG_OP_SAR,   0,  2, -1 },
    /* ROL runs as ROR by the width less the count; see rcg_emit(). */
    { gen_ROL,    RCG_OP_ROR,   0,  2, -1 },
    { gen_ROR,    RCG_OP_ROR,   0,  2, -1 },
    { gen_CALL,   RCG_OP_CALL, -1, -1, -1 },
    { gen_CALL_m, RCG_OP_CALL, -1,  1, -1 },
    { gen_JMP_m,  RCG_OP_JMP,  -1,  1, -1 },
    { gen_RET,    RCG_OP_RET,  -1, -1, -1 },
};

/*
 * An operand's kind, as a form names it: register, memory or immediate, or
 * 0 if no form takes it.
 */
static char rcg_kind(DisasContext *s, X86DecodedOp *op)
{
    /* Check has_ea first: decode-new gives LEA's memory operand no unit. */
    if (op->has_ea) {
        return 'm';
    }
    switch (op->unit) {
    case X86_OP_INT:
        /* AH, CH, DH and BH are left to TCG. */
        if (op->ot == MO_8 && byte_reg_is_xH(s, op->n)) {
            return 0;
        }
        return 'r';
    case X86_OP_IMM:
        return 'i';
    default:
        return 0;
    }
}

static int rcg_form(char a, char b)
{
    static const char *const names[RCG_NB_FORMS] = {
        [RCG_FORM_RR] = "rr", [RCG_FORM_RM] = "rm", [RCG_FORM_MR] = "mr",
        [RCG_FORM_RI] = "ri", [RCG_FORM_MI] = "mi", [RCG_FORM_R] = "r",
        [RCG_FORM_I] = "i", [RCG_FORM_M] = "m",
    };

    for (int i = 0; i < RCG_NB_FORMS; i++) {
        if (names[i][0] == a && names[i][1] == b) {
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
 * Adds v's temp to list unless it is already there. Each list has room for
 * RCG_MAX_WORDS.
 */
static void rcg_note(TCGTemp **list, unsigned *n, TCGv v)
{
    TCGTemp *g = tcgv_tl_temp(v);

    for (unsigned i = 0; i < *n; i++) {
        if (list[i] == g) {
            return;
        }
    }
    tcg_debug_assert(*n < RCG_MAX_WORDS);
    list[(*n)++] = g;
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
    } else if (cc_op == CC_OP_EFLAGS) {
        return RCG_CC_EFLAGS;
    }
    return -1;
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

        if (!gadget) {
            return NULL;
        }
        /*
         * As gen_Jcc, but the gadget always stores CC_OP, even where it is
         * already clean (after COMISS, FCOMI or PUSHF, for example).
         */
        taken = gen_new_label();
        gen_bnd_jmp(s);
        tcg_gen_rich_br(gadget, &word, 1, taken, &out, 1, flags_in, 2);
        s->cc_op_dirty = false;
        gen_conditional_jump_labels(s, decode->immediate, NULL, taken);
        return gadget;
    }
    if (gen == gen_SETcc) {
        X86DecodedOp *d = &decode->op[0];
        const void *gadget = rcg_setcc[cc][cond];
        uint64_t word;
        TCGTemp *out, *ins[3] = { flags_in[0], flags_in[1] };

        if (!gadget || rcg_kind(s, d) != 'r') {
            return NULL;
        }
        word = rcg_reg(d->n);
        /* It writes the low byte, so it reads the rest of the register. */
        out = ins[2] = tcgv_tl_temp(cpu_regs[d->n]);
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
static bool rcg_select(X86DecodedInsn *decode, RCGOp *op,
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

    if (*op == RCG_OP_SUB && !writes) {
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
    case RCG_KIND_SHIFT: {
        /*
         * By an immediate count, or 1; a count in CL is left to TCG. So is
         * a count that masks to 0: TCG then keeps the flags but still
         * writes the operand back, which zero-extends a 32-bit register.
         */
        char a = rcg_kind(s, first);

        *ot = first->ot;
        if (second->unit == X86_OP_IMM) {
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
    bool ordered = false, rotate_left = false;
    const RCGSlot *slot;
    const RCGGadget *g;
    uint64_t words[RCG_MAX_WORDS];
    TCGTemp *outs[RCG_MAX_WORDS], *ins[RCG_MAX_WORDS];
    TCGv cf = NULL;
    unsigned n, nb_outs = 0, nb_ins = 0;

    if (!CODE64(s) || s->aflag != MO_64 || (s->prefix & PREFIX_LOCK)) {
        return NULL;
    }
    if (gen == gen_Jcc || gen == gen_SETcc || gen == gen_CMOVcc) {
        return rcg_translate_cond(s, decode);
    }
    if (!rcg_select(decode, &op, &first, &second)) {
        return NULL;
    }
    facts = &rcg_facts[op];

    form = rcg_operands(s, decode, op, first, second, &ot, &imm,
                        &rotate_left);
    if (form < 0) {
        return NULL;
    }
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
    if (facts->branch && !(op == RCG_OP_CALL && form == RCG_FORM_I)) {
        rcg_note(outs, &nb_outs, cpu_eip);
    }
    for (n = 0; n < RCG_MAX_WORDS && g->words[n] != RCG_W_END; n++) {
        if (g->words[n] == RCG_W_D) {
            rcg_note(outs, &nb_outs, cpu_regs[first->n]);
            if (facts->reads_d || ot < MO_32) {
                rcg_note(ins, &nb_ins, cpu_regs[first->n]);
            }
        }
    }
    if (facts->dst) {
        rcg_note(outs, &nb_outs, cpu_cc_dst);
    }
    if (facts->src) {
        rcg_note(outs, &nb_outs, cpu_cc_src);
    }

    /* The words, in the order the gadget takes them, and what it reads. */
    for (n = 0; n < RCG_MAX_WORDS && g->words[n] != RCG_W_END; n++) {
        AddressParts *a = &decode->mem;

        switch (g->words[n]) {
        case RCG_W_D:
            words[n] = rcg_reg(first->n);
            break;
        case RCG_W_S1:
            words[n] = rcg_reg(first->n);
            rcg_note(ins, &nb_ins, cpu_regs[first->n]);
            break;
        case RCG_W_S:
            words[n] = rcg_reg(second->n);
            rcg_note(ins, &nb_ins, cpu_regs[second->n]);
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
        default:
            g_assert_not_reached();
        }
    }
    /*
     * INC and DEC keep CF, which gen_INC and gen_DEC put in cc_src: take it
     * from the flags state the gadget replaces, and store it after the
     * gadget, so that a fault in the gadget finds that state as it was.
     */
    if (facts->cf) {
        cf = tcg_temp_new();
        gen_compute_eflags_c(s, cf);
    }
    tcg_gen_rich(g->gadget, words, n, slot->access ? TCG_RICH_MAY_FAULT : 0,
                 outs, nb_outs, ins, nb_ins);
    if (facts->cf) {
        tcg_gen_mov_tl(cpu_cc_src, cf);
    }

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

    /* Record the lazy-flags state the gadget left. */
    if (facts->cc_op >= 0) {
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
