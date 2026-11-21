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
    { gen_INC,    RCG_OP_INC,   0, -1, X86_SPECIAL_HasLock },
    { gen_DEC,    RCG_OP_DEC,   0, -1, X86_SPECIAL_HasLock },
    { gen_BSWAP,  RCG_OP_BSWAP, 0, -1, -1 },
    /* The second operand of a shift or rotate is its count. */
    { gen_SHL,    RCG_OP_SHL,   0,  2, -1 },
    { gen_SHR,    RCG_OP_SHR,   0,  2, -1 },
    { gen_SAR,    RCG_OP_SAR,   0,  2, -1 },
    /* ROL runs as ROR by the width less the count; see rcg_operands(). */
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
    /*
     * The SSE floating-point ops (ADD, SUB, MUL, DIV, SQRT, MIN and MAX), by
     * their ps op: rcg_select() picks pd, ss or sd by the prefix. op[1] is
     * the destination again in the legacy encodings, and VEX.vvvv's
     * register in the VEX ones, for which rcg_vex_op() picks the op. Packed
     * SQRT has no op[1]: decode_sse_unary() leaves it out.
     */
    { gen_VADD,   RCG_OP_ADDPS, 0, 2, -1 },
    { gen_VSUB,   RCG_OP_SUBPS, 0, 2, -1 },
    { gen_VMUL,   RCG_OP_MULPS, 0, 2, -1 },
    { gen_VDIV,   RCG_OP_DIVPS, 0, 2, -1 },
    { gen_VSQRT,  RCG_OP_SQRTPS, 0, 2, -1 },
    { gen_VMIN,   RCG_OP_MINPS, 0, 2, -1 },
    { gen_VMAX,   RCG_OP_MAXPS, 0, 2, -1 },
    /*
     * UCOMISS and COMISS, which compare op[1] with op[2] and write neither;
     * rcg_select() picks sd by the prefix.
     */
    { gen_VUCOMI, RCG_OP_UCOMISS, 1, 2, -1 },
    { gen_VCOMI,  RCG_OP_COMISS,  1, 2, -1 },
    /* UNPCKLPS and UNPCKHPS; rcg_select() picks pd by the prefix. */
    { gen_VUNPCKLPx, RCG_OP_UNPCKLPS, 0, 2, -1 },
    { gen_VUNPCKHPx, RCG_OP_UNPCKHPS, 0, 2, -1 },
    /*
     * The integer unpacks of 32 and 64 bits, which call the same helpers as
     * UNPCKLPS to UNPCKHPD. Their MMX forms have no gadget: rcg_kind()
     * refuses MMX registers.
     */
    { gen_PUNPCKLDQ,  RCG_OP_UNPCKLPS, 0, 2, -1 },
    { gen_PUNPCKHDQ,  RCG_OP_UNPCKHPS, 0, 2, -1 },
    { gen_PUNPCKLQDQ, RCG_OP_UNPCKLPD, 0, 2, -1 },
    { gen_PUNPCKHQDQ, RCG_OP_UNPCKHPD, 0, 2, -1 },
    /*
     * PAND to PXOR, which ANDPS to XORPS and their pd forms also decode to.
     * op[1] is as for the floating-point ops.
     */
    { gen_PAND,   RCG_OP_PAND,  0, 2, -1 },
    { gen_PANDN,  RCG_OP_PANDN, 0, 2, -1 },
    { gen_POR,    RCG_OP_POR,   0, 2, -1 },
    { gen_PXOR,   RCG_OP_PXOR,  0, 2, -1 },
    /*
     * MOVD and MOVQ to and from general registers, and MOVQ between XMM
     * registers; with memory, rcg_select() picks MOVSS or MOVSD. Their MMX
     * forms have no gadget, as for the unpacks.
     */
    { gen_MOVD_to,   RCG_OP_MOVD, 0, 2, -1 },
    { gen_MOVD_from, RCG_OP_MOVD, 0, 2, -1 },
    { gen_MOVQ,      RCG_OP_MOVD, 0, 2, -1 },
    /*
     * Table shuffles, by a table that rcg_tbl_table() works out: of the
     * source alone (RCG_OP_TBL1), which is op[1] for PSHUFD, PSHUFLW,
     * PSHUFHW, PSRLDQ and PSLLDQ and op[2] for the broadcasts, or of the
     * first input, op[1], and the source, op[2] (RCG_OP_TBL2). op[1] is the
     * destination again in the legacy encodings, and VEX.vvvv's register in
     * the VEX ones. The MMX forms of the unpacks and of PALIGNR have no
     * gadget: rcg_kind() refuses MMX registers.
     */
    { gen_PSHUFD,       RCG_OP_TBL1, 0, 1, -1 },
    { gen_PSHUFLW,      RCG_OP_TBL1, 0, 1, -1 },
    { gen_PSHUFHW,      RCG_OP_TBL1, 0, 1, -1 },
    { gen_PSRLDQ_i,     RCG_OP_TBL1, 0, 1, -1 },
    { gen_PSLLDQ_i,     RCG_OP_TBL1, 0, 1, -1 },
    { gen_VPBROADCASTB, RCG_OP_TBL1, 0, 2, -1 },
    { gen_VPBROADCASTW, RCG_OP_TBL1, 0, 2, -1 },
    { gen_VPBROADCASTD, RCG_OP_TBL1, 0, 2, -1 },
    { gen_VPBROADCASTQ, RCG_OP_TBL1, 0, 2, -1 },
    { gen_PUNPCKLBW,    RCG_OP_TBL2, 0, 2, -1 },
    { gen_PUNPCKLWD,    RCG_OP_TBL2, 0, 2, -1 },
    { gen_PUNPCKHBW,    RCG_OP_TBL2, 0, 2, -1 },
    { gen_PUNPCKHWD,    RCG_OP_TBL2, 0, 2, -1 },
    { gen_PALIGNR,      RCG_OP_TBL2, 0, 2, -1 },
    /*
     * The same for the floating-point shuffles. MOVDDUP, MOVSLDUP and
     * MOVSHDUP take their source as op[2], like the broadcasts, and
     * VPERMILPS and VPERMILPD by an immediate as op[1], like PSHUFD. MOVHPS
     * and MOVHPD load memory into the register's high lane, and MOVLPS and
     * MOVLPD into its low lane. All four store as MOVSD does, MOVHPS and
     * MOVHPD from byte 8 of the register (see rcg_emit()). SHUFPS and
     * SHUFPD share gen_VSHUF, and BLENDPS and VPBLENDD share gen_VBLENDPS.
     */
    { gen_VMOVDDUP,     RCG_OP_TBL1, 0, 2, -1 },
    { gen_VMOVSLDUP,    RCG_OP_TBL1, 0, 2, -1 },
    { gen_VMOVSHDUP,    RCG_OP_TBL1, 0, 2, -1 },
    { gen_VPERMILPS_i,  RCG_OP_TBL1, 0, 1, -1 },
    { gen_VPERMILPD_i,  RCG_OP_TBL1, 0, 1, -1 },
    { gen_VSHUF,        RCG_OP_TBL2, 0, 2, -1 },
    { gen_VMOVLHPS,     RCG_OP_TBL2, 0, 2, -1 },
    { gen_VMOVHLPS,     RCG_OP_TBL2, 0, 2, -1 },
    { gen_VMOVHPx_ld,   RCG_OP_TBL2, 0, 2, -1 },
    { gen_VMOVLPx_ld,   RCG_OP_TBL2, 0, 2, -1 },
    { gen_VINSERTPS_r,  RCG_OP_TBL2, 0, 2, -1 },
    { gen_VINSERTPS_m,  RCG_OP_TBL2, 0, 2, -1 },
    { gen_VBLENDPS,     RCG_OP_TBL2, 0, 2, -1 },
    { gen_VBLENDPD,     RCG_OP_TBL2, 0, 2, -1 },
    { gen_VPBLENDW,     RCG_OP_TBL2, 0, 2, -1 },
    { gen_VMOVHPx_st,   RCG_OP_MOVSD, 0, 2, -1 },
};

/* Each op's ps, pd, ss and sd, in this order: see rcg_select(). */
QEMU_BUILD_BUG_ON(RCG_OP_ADDSD != RCG_OP_ADDPS + 3 ||
                  RCG_OP_SUBPS != RCG_OP_ADDPS + 4 ||
                  RCG_OP_MULPS != RCG_OP_ADDPS + 8 ||
                  RCG_OP_DIVSD != RCG_OP_ADDPS + 15 ||
                  RCG_OP_SQRTSD != RCG_OP_ADDPS + 19 ||
                  RCG_OP_MINPS != RCG_OP_ADDPS + 20 ||
                  RCG_OP_MAXSD != RCG_OP_ADDPS + 27 ||
                  RCG_OP_UCOMISD != RCG_OP_UCOMISS + 1 ||
                  RCG_OP_COMISS != RCG_OP_UCOMISS + 2 ||
                  RCG_OP_COMISD != RCG_OP_COMISS + 1 ||
                  RCG_OP_UNPCKLPD != RCG_OP_UNPCKLPS + 1 ||
                  RCG_OP_UNPCKHPD != RCG_OP_UNPCKHPS + 1);

/* The VEX encodings' ops, in the order of the legacy ones: rcg_vex_op(). */
QEMU_BUILD_BUG_ON(RCG_OP_VMOVSS - RCG_OP_VMOVDQA !=
                  RCG_OP_MOVSS - RCG_OP_MOVDQA ||
                  RCG_OP_VMAXSD - RCG_OP_VADDPS !=
                  RCG_OP_MAXSD - RCG_OP_ADDPS ||
                  RCG_OP_VUNPCKHPD - RCG_OP_VUNPCKLPS !=
                  RCG_OP_UNPCKHPD - RCG_OP_UNPCKLPS ||
                  RCG_OP_VPXOR - RCG_OP_VPAND != RCG_OP_PXOR - RCG_OP_PAND ||
                  RCG_OP_VTBL2 - RCG_OP_VTBL1 != RCG_OP_TBL2 - RCG_OP_TBL1);

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
        /* AH to BH too; see rcg_is_xh(). */
        return 'r';
    case X86_OP_IMM:
        return 'i';
    case X86_OP_SSE:
        /*
         * rcg_operands() takes the width from the RCG op, for MOVD and MOVQ
         * from the general register (64 bits between XMM registers), and for
         * a table shuffle from memory from the memory operand. A VEX.256
         * encoding works on the whole YMM register, which no gadget does; a
         * VEX.128 one takes the op rcg_vex_op() picks.
         */
        return (s->prefix & PREFIX_VEX) && s->vex_l ? 0 : 'x';
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
        [RCG_FORM_MX] = "mx", [RCG_FORM_XR] = "xr", [RCG_FORM_RX] = "rx",
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
 * Whether op is AH, CH, DH or BH. A gadget takes one as the second byte of
 * RAX to RBX (see rcg_reg_op()), reading eight bytes from there, where TCG
 * reads the register shifted down by 8 (gen_op_mov_v_reg()). Both have AH
 * to BH as their low byte, and the gadgets use no more of an 8-bit
 * register than that: the low byte of a MOV, XCHG, ALU or unary result
 * depends on no higher bit, and the shifts, MUL, IMUL, MOVZX and MOVSX
 * extend their operands from 8 bits first. Where the flags state they
 * leave differs from TCG's, it differs only above the width, which nothing
 * reads, as with TCG's state for AL to BL, which holds the rest of the
 * register above the width. ROL and ROR of AH to BH stay with TCG: see
 * rcg_operands().
 */
static bool rcg_is_xh(DisasContext *s, X86DecodedOp *op)
{
    return op->unit == X86_OP_INT && !op->has_ea && op->ot == MO_8 &&
           byte_reg_is_xH(s, op->n);
}

/*
 * A register operand's env offset, as a gadget takes it, and *v, the
 * global it is in: AH to BH are the second byte of RAX to RBX. An XMM
 * register is in env alone, so *v is NULL. *v is for noting what the gadget
 * reads and writes: for AH to BH it holds all of RAX to RBX, so code that
 * reads its value must refuse them or shift it down by 8.
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
    } else if (cc_op == CC_OP_ADCX) {
        return RCG_CC_ADCX;
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
         * after a setter in rcg_fused_setter, one gadget does both,
         * branching on the values it compared rather than reloading cc_dst
         * and cc_src.
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
 * After the gadget has rotated register reg (width ot) right by count
 * (less than the width), sets CF and OF as gen_ROL and gen_ROR do and keeps
 * the other flags. Those leave CC_OP_ADCOX; this leaves CC_OP_EFLAGS, with
 * every flag in cc_src. These ops are removed as dead if the flags are set
 * again before anything reads them.
 */
static void rcg_rotate_flags(DisasContext *s, MemOp ot, TCGv reg, bool left,
                             int count)
{
    TCGv flags = tcg_temp_new(), bit = tcg_temp_new();
    int top = (8 << ot) - 1;

    gen_mov_eflags(s, flags);
    /*
     * CF: the bit that went round. OF: whether the top bit changed. The
     * old top bit is the result's bit top - count, which the shift moves
     * up to it; the register's bits above the width cannot reach it.
     */
    tcg_gen_extract_tl(bit, reg, left ? 0 : top, 1);
    tcg_gen_deposit_tl(flags, flags, bit, ctz32(CC_C), 1);
    tcg_gen_shli_tl(bit, reg, count);
    tcg_gen_xor_tl(bit, bit, reg);
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
    } else if (rcg_facts[*op].kind == RCG_KIND_VFP) {
        /* ps, pd, ss or sd, by the prefix: gen_fp_sse()'s choice. */
        *op += s->prefix & PREFIX_REPZ ? 2 : s->prefix & PREFIX_REPNZ ? 3 :
               s->prefix & PREFIX_DATA ? 1 : 0;
    } else if (rcg_facts[*op].kind == RCG_KIND_VCOMI ||
               gen == gen_VUNPCKLPx || gen == gen_VUNPCKHPx) {
        /*
         * ps or pd (for UCOMIS and COMIS, ss or sd) by the 0x66 prefix;
         * decode-new allows no other prefix. The integer unpacks name their
         * op in rcg_insns[] already.
         */
        *op += s->prefix & PREFIX_DATA ? 1 : 0;
    } else if (*op == RCG_OP_MOVD && ((*first)->has_ea || (*second)->has_ea)) {
        /*
         * With memory, MOVD and MOVQ load as MOVSS and MOVSD do, clearing
         * the rest of the register, and store only the low lane. The memory
         * operand is E,y, of 32 or 64 bits, but for gen_MOVQ, whose store
         * decode-new gives a W,dq destination though it writes 64 bits.
         */
        X86DecodedOp *e = (*first)->has_ea ? *first : *second;
        MemOp ot = gen == gen_MOVQ ? MO_64 : e->ot;

        *op = ot == MO_64 ? RCG_OP_MOVSD : RCG_OP_MOVSS;
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
 * Whether float_status keeps its exception flags in its first two bytes,
 * where the SSE ADD, SUB, MUL, DIV and SQRT gadgets read them with LDRH.
 */
static bool rcg_sse_flags_ok(void)
{
    static int ok = -1;

    if (ok < 0) {
        float_status st = { 0 };
        uint16_t flags;

        set_float_exception_flags(float_flag_inexact | float_flag_invalid,
                                  &st);
        memcpy(&flags, &st, sizeof(flags));
        ok = flags == (float_flag_inexact | float_flag_invalid);
    }
    return ok;
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
    case RCG_KIND_VMOVD: {
        /*
         * MOVD and MOVQ with a general register take its width; MOVQ
         * between XMM registers is 64 bits. rcg_select() has already sent
         * the memory forms to MOVSS and MOVSD.
         */
        char a = rcg_kind(s, first), b = rcg_kind(s, second);

        *ot = a == 'r' ? first->ot : b == 'r' ? second->ot : MO_64;
        if (!a || !b || (*ot != MO_32 && *ot != MO_64)) {
            return -1;
        }
        return rcg_form(a, b);
    }
    case RCG_KIND_VFP:
    case RCG_KIND_VLANE:
    case RCG_KIND_VLOGIC:
    case RCG_KIND_VTBL: {
        /*
         * ss and sd take the low lane of the source; ps and pd, the unpacks,
         * the logic ops and the table shuffles take all 16 bytes, which in
         * memory need LSE2, as for MOVDQA, and must be aligned in the legacy
         * encodings, whose gadgets require it, and may be misaligned in the
         * VEX ones, whose gadgets allow it. A table shuffle's source in
         * memory may instead be 1 to 8 bytes (see rcg_tbl_table()), which
         * have no alignment to keep. All the floating-point gadgets but
         * MIN's and MAX's read float_status's flags directly;
         * rcg_sse_flags_ok() also gates MIN and MAX, which do not need it.
         * The other gadgets raise nothing.
         */
        char a = rcg_kind(s, first), b = rcg_kind(s, second);
        bool fp = rcg_facts[op].kind == RCG_KIND_VFP;
        bool vex = s->prefix & PREFIX_VEX;
        int type = fp ? (op - RCG_OP_ADDPS) % 4 : 0;

        if (rcg_facts[op].kind == RCG_KIND_VTBL) {
            *ot = b == 'm' ? second->ot : MO_128;
        } else {
            *ot = type == 2 ? MO_32 : type == 3 ? MO_64 : MO_128;
        }
        if (a != 'x' || !b ||
            (b == 'm' && *ot == MO_128 &&
             (!(cpuinfo & CPUINFO_LSE2) ||
              sse_needs_alignment(s, decode, MO_128) == vex)) ||
            (fp && !rcg_sse_flags_ok())) {
            return -1;
        }
        return rcg_form(a, b);
    }
    case RCG_KIND_VCOMI: {
        /* The low lanes; memory is just the lane, which may be misaligned. */
        char a = rcg_kind(s, first), b = rcg_kind(s, second);

        *ot = (op - RCG_OP_UCOMISS) % 2 ? MO_64 : MO_32;
        return a == 'x' && b ? rcg_form(a, b) : -1;
    }
    case RCG_KIND_LEAVE:
        /* Only a 64-bit RBP. */
        *ot = mo_pushpop(s, s->dflag);
        return *ot == MO_64 ? RCG_FORM_R : -1;
    case RCG_KIND_BT: {
        char a = rcg_kind(s, first), b = rcg_kind(s, second);

        /*
         * After CC_OP_DYNAMIC, TCG computes the flags in full (see
         * gen_bt_flags()), and a gadget there timed slower. With the bit
         * number in a register, a memory operand is a bit string that can
         * reach beyond the operand, so that is left to TCG too.
         */
        *ot = first->ot;
        if (s->cc_op == CC_OP_DYNAMIC || !a || !b || (a == 'm' && b == 'r')) {
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
         * does the same for a count of 0 itself. ROL and ROR by CL, and of
         * AH to BH, are left to TCG.
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
             * ROL and ROR of a register, by the masked count modulo the
             * width. Only at 8 and 16 bits can that be 0 when the masked
             * count is not. ROL by n is ROR by the width less n. Not AH to
             * BH: rcg_rotate_flags() takes CF and OF from the low bits of
             * the register's global, which for them hold AL to BL.
             */
            int bits = 8 << *ot;

            if (a != 'r' || rcg_is_xh(s, first)) {
                return -1;
            }
            *rotate_left = decode->e.gen == gen_ROL;
            *imm = (*rotate_left ? -*imm : *imm) & (bits - 1);
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
 * Packs the words of g, a gadget that accesses memory, into stream words,
 * matching rcg-gen.py's stream_words(): the narrow words two to a stream
 * word, the first in the low half, then the odd one out alone, then each
 * of the others alone. Returns how many stream words there are. Only the
 * RCG tests, which take every gadget (rcg-gen.py --coverage), check that
 * the two layouts agree.
 */
static unsigned rcg_pack_words(const RCGGadget *g, uint64_t *words,
                               unsigned n)
{
    uint64_t out[RCG_MAX_WORDS];
    unsigned nb = 0, i;
    bool odd = false;

    for (i = 0; i < n; i++) {
        if (!rcg_word_narrow(g->words[i])) {
            continue;
        }
        tcg_debug_assert((int32_t)words[i] == (int64_t)words[i]);
        if (odd) {
            out[nb - 1] = deposit64(out[nb - 1], 32, 32, words[i]);
        } else {
            out[nb++] = words[i];
        }
        odd = !odd;
    }
    for (i = 0; i < n; i++) {
        if (!rcg_word_narrow(g->words[i])) {
            out[nb++] = words[i];
        }
    }
    memcpy(words, out, nb * sizeof(uint64_t));
    return nb;
}

/*
 * The op of a VEX.128 encoding of op, in form, or -1 if it has none. Its
 * gadgets take VEX.vvvv's register as their first input where the
 * instruction has one, and clear bits 128 to 255 of the destination
 * register. A move to memory or to a general register is the same as the
 * legacy encoding and uses its gadgets; so do UCOMIS and COMIS, which
 * write no XMM register.
 */
static int rcg_vex_op(RCGOp op, int form)
{
    switch (rcg_facts[op].kind) {
    case RCG_KIND_VMOV:
        return form == RCG_FORM_MX ? op : op - RCG_OP_MOVDQA + RCG_OP_VMOVDQA;
    case RCG_KIND_VFP:
        return op - RCG_OP_ADDPS + RCG_OP_VADDPS;
    case RCG_KIND_VLANE:
        return op - RCG_OP_UNPCKLPS + RCG_OP_VUNPCKLPS;
    case RCG_KIND_VLOGIC:
        return op - RCG_OP_PAND + RCG_OP_VPAND;
    case RCG_KIND_VMOVD:
        return form == RCG_FORM_RX ? op : RCG_OP_VMOVD;
    case RCG_KIND_VTBL:
        return op - RCG_OP_TBL1 + RCG_OP_VTBL1;
    case RCG_KIND_VCOMI:
        return op;
    default:
        return -1;
    }
}

/* A table shuffle's table entry for a byte past the inputs, which gives 0. */
#define RCG_TBL_ZERO 0xff

QEMU_BUILD_BUG_ON(RCG_TABLE_WORDS * 8 != 16);

/*
 * The table of a table shuffle for decode's instruction, whose source is
 * second. Byte i of the result is byte t[i] of the inputs: with two inputs,
 * bytes 0 to 15 are the first input's and 16 to 31 the source's; with one,
 * bytes 0 to 15 are the source's. Where t[i] is RCG_TBL_ZERO, the result's
 * byte is 0. A source in memory narrower than 16 bytes is at byte 0. For a
 * broadcast and MOVDDUP, byte 0 is also where a register source's element
 * is. For MOVHPS, MOVHPD, MOVLPS and MOVLPD it is the loaded lane. For
 * INSERTPS it is the element, which replaces the one that bits 6 and 7 pick
 * from a register source. The tables give the same results as TCG's helpers
 * and gvec ops.
 */
static void rcg_tbl_table(DisasContext *s, X86DecodedInsn *decode,
                          X86DecodedOp *second, uint8_t *t)
{
    X86GenFunc gen = decode->e.gen;
    unsigned imm = decode->immediate & 0xff;
    int i, k;

    if (gen == gen_PSHUFD || gen == gen_VPERMILPS_i ||
        gen == gen_VPERMILPD_i || gen == gen_VSHUF) {
        /*
         * Element n, of 4 or 8 bytes, is the source's element that field n
         * of the immediate picks; for SHUFPS and SHUFPD (gen_VSHUF picks
         * SHUFPD by the data size prefix), the low half picks from the
         * first input instead.
         */
        bool pd = gen == gen_VPERMILPD_i ||
                  (gen == gen_VSHUF && (s->prefix & PREFIX_DATA));
        int size = pd ? 8 : 4, bits = pd ? 1 : 2;

        for (i = 0; i < 16; i++) {
            int pick = (imm >> (i / size * bits)) & ((1 << bits) - 1);

            t[i] = (gen == gen_VSHUF && i >= 8 ? 16 : 0) + pick * size +
                   i % size;
        }
    } else if (gen == gen_PSHUFLW || gen == gen_PSHUFHW) {
        /* One half's words shuffled; the other half unchanged. */
        int half = gen == gen_PSHUFHW ? 8 : 0;

        for (i = 0; i < 16; i++) {
            t[i] = i;
        }
        for (i = 0; i < 8; i++) {
            t[half + i] = half + ((imm >> (i / 2 * 2)) & 3) * 2 + i % 2;
        }
    } else if (gen == gen_PSRLDQ_i || gen == gen_PSLLDQ_i) {
        int shift = imm;

        for (i = 0; i < 16; i++) {
            k = gen == gen_PSRLDQ_i ? i + shift : i - shift;
            t[i] = k >= 0 && k < 16 ? k : RCG_TBL_ZERO;
        }
    } else if (gen == gen_VPBROADCASTB || gen == gen_VPBROADCASTW ||
               gen == gen_VPBROADCASTD || gen == gen_VPBROADCASTQ) {
        int size = 1 << second->ot;

        for (i = 0; i < 16; i++) {
            t[i] = i % size;
        }
    } else if (gen == gen_VMOVDDUP || gen == gen_VMOVSLDUP ||
               gen == gen_VMOVSHDUP) {
        /*
         * Element n is the source's element n rounded down to even, or for
         * MOVSHDUP up to odd, with elements of 8 bytes for MOVDDUP and 4
         * for the others.
         */
        int size = gen == gen_VMOVDDUP ? 8 : 4;
        int odd = gen == gen_VMOVSHDUP;

        for (i = 0; i < 16; i++) {
            t[i] = ((i / size & ~1) | odd) * size + i % size;
        }
    } else if (gen == gen_VMOVLHPS || gen == gen_VMOVHPx_ld ||
               gen == gen_VMOVHLPS || gen == gen_VMOVLPx_ld) {
        /*
         * The first input's low or high lane, kept in place, and a lane of
         * the source in the other. MOVLHPS and the MOVHPS and MOVHPD loads
         * keep the low lane and put the source's low lane above it. MOVHLPS
         * keeps the high lane and puts the source's high lane below it, and
         * the MOVLPS and MOVLPD loads put the source's low lane there.
         */
        int keep = gen == gen_VMOVLHPS || gen == gen_VMOVHPx_ld ? 0 : 1;
        int take = gen == gen_VMOVHLPS ? 1 : 0;

        for (i = 0; i < 16; i++) {
            t[i] = i / 8 == keep ? i : 16 + take * 8 + i % 8;
        }
    } else if (gen == gen_VINSERTPS_r || gen == gen_VINSERTPS_m) {
        /*
         * The first input, with the element that bits 4 and 5 pick replaced
         * by the source's element (bits 6 and 7 pick it from a register),
         * then each element n whose bit n is set in bits 0 to 3 cleared, as
         * in gen_vinsertps().
         */
        int from = gen == gen_VINSERTPS_r ? (imm >> 6) & 3 : 0;
        int to = (imm >> 4) & 3;

        for (i = 0; i < 16; i++) {
            int element = i / 4;

            t[i] = (imm >> element) & 1 ? RCG_TBL_ZERO :
                   element == to ? 16 + from * 4 + i % 4 : i;
        }
    } else if (gen == gen_VBLENDPS || gen == gen_VBLENDPD ||
               gen == gen_VPBLENDW) {
        /* Element n from the source if bit n of the immediate is set. */
        int size = gen == gen_VBLENDPD ? 8 : gen == gen_VBLENDPS ? 4 : 2;

        for (i = 0; i < 16; i++) {
            t[i] = ((imm >> (i / size)) & 1 ? 16 : 0) + i;
        }
    } else if (gen == gen_PALIGNR) {
        /*
         * The two inputs as one of 32 bytes, the source in the low half,
         * shifted right by imm bytes: 0 from imm 32 on.
         */
        for (i = 0; i < 16; i++) {
            k = i + imm;
            t[i] = k < 16 ? 16 + k : k < 32 ? k - 16 : RCG_TBL_ZERO;
        }
    } else if (gen == gen_PUNPCKLBW || gen == gen_PUNPCKLWD ||
               gen == gen_PUNPCKHBW || gen == gen_PUNPCKHWD) {
        /*
         * The low or high halves of the first input and the source,
         * interleaved by elements of 1 or 2 bytes, the first input's first.
         */
        int size = gen == gen_PUNPCKLWD || gen == gen_PUNPCKHWD ? 2 : 1;
        int half = gen == gen_PUNPCKHBW || gen == gen_PUNPCKHWD ? 8 : 0;

        for (i = 0; i < 16; i++) {
            int element = i / (2 * size);
            int from_source = i / size % 2;

            t[i] = from_source * 16 + half + element * size + i % size;
        }
    } else {
        /* The gadget is already emitted, so it is too late to refuse. */
        g_assert_not_reached();
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
    bool ordered = false, rotate_left = false, by_cl;
    const RCGSlot *slot;
    const RCGGadget *g;
    uint64_t words[RCG_MAX_WORDS + RCG_TABLE_WORDS];
    TCGTemp *outs[RCG_MAX_WORDS], *ins[RCG_MAX_WORDS];
    TCGv cf = NULL, kept_eflags = NULL;
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
    if (s->prefix & PREFIX_VEX) {
        int vex_op = rcg_vex_op(op, form);

        if (vex_op < 0) {
            return NULL;
        }
        op = vex_op;
        facts = &rcg_facts[op];
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
    if (facts->cf == RCG_CF_SRC2) {
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
        if (ot == MO_128) {
            /*
             * The atomicity of gen_ldo_env_A0() and gen_sto_env_A0(), with
             * MO_ALIGN_16 where sse_needs_alignment() holds: for MOVDQA,
             * MOVAPS and MOVAPD in either encoding, as rcg_select() picks
             * them, and for the legacy encodings of the floating-point,
             * unpack, logic and table shuffle ops, which rcg_operands()
             * requires.
             */
            memop |= (s->cpuid_ext_features & CPUID_EXT_AVX
                      ? MO_ATOM_IFALIGN : MO_ATOM_IFALIGN_PAIR) |
                     (sse_needs_alignment(s, decode, MO_128)
                      ? MO_ALIGN_16 : 0);
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
    if (facts->env_cc_op) {
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_cc_op));
    }
    if (by_cl) {
        /* With a count of 0 it keeps the flags state, cc_op included. */
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_cc_op));
        rcg_note(ins, &nb_ins, cpu_cc_dst);
        rcg_note(ins, &nb_ins, cpu_cc_src);
        rcg_note_temp(ins, &nb_ins, tcgv_i32_temp(cpu_cc_op));
    }

    /* The words, in g->words' order, and what the gadget reads. */
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
            if (gen == gen_VMOVHPx_st) {
                /* MOVSD's gadget, storing the high lane. */
                words[n] += offsetof(XMMReg, XMM_Q(1));
            }
            rcg_note(ins, &nb_ins, reg);
            break;
        case RCG_W_V:
            /* VEX.vvvv's register, an XMM register, which is in env alone. */
            words[n] = rcg_reg_op(s, &decode->op[1], &reg);
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
    /*
     * CF, from the flags state before the instruction. ADC and SBB read it
     * in cc_src2. INC and DEC keep it in cc_src, as gen_INC and gen_DEC do,
     * written after the gadget, so that a fault in the gadget finds that
     * state as it was.
     */
    if (facts->cf != RCG_CF_NONE) {
        cf = tcg_temp_new();
        gen_compute_eflags_c(s, cf);
    }
    if (facts->cf == RCG_CF_SRC2) {
        tcg_gen_mov_tl(cpu_cc_src2, cf);
        rcg_note(ins, &nb_ins, cpu_cc_src2);
    }
    /*
     * After a state with EFLAGS in cc_src, BT keeps those EFLAGS and puts
     * CF in cc_dst, as gen_bt_flags() does. They are saved here, as the
     * gadget overwrites cc_src, and CF is bit 0 of what it wrote.
     */
    if (facts->kind == RCG_KIND_BT && CC_OP_HAS_EFLAGS(s->cc_op)) {
        kept_eflags = tcg_temp_new();
        tcg_gen_mov_tl(kept_eflags, cpu_cc_src);
    }
    if (slot->access) {
        n = rcg_pack_words(g, words, n);
    }
    if (facts->kind == RCG_KIND_VTBL) {
        rcg_tbl_table(s, decode, second, (uint8_t *)&words[n]);
        n += RCG_TABLE_WORDS;
    }
    tcg_gen_rich(g->gadget, words, n, slot->access ? TCG_RICH_MAY_FAULT : 0,
                 outs, nb_outs, ins, nb_ins);
    if (facts->cf == RCG_CF_SRC) {
        tcg_gen_mov_tl(cpu_cc_src, cf);
    }
    if (kept_eflags) {
        tcg_gen_andi_tl(cpu_cc_dst, cpu_cc_src, 1);
        tcg_gen_mov_tl(cpu_cc_src, kept_eflags);
    }

    if (op == RCG_OP_ROR) {
        /* rcg_operands() leaves ROL and ROR of AH to BH to TCG. */
        tcg_debug_assert(!rcg_is_xh(s, first));
        rcg_reg_op(s, first, &reg);
        rcg_rotate_flags(s, ot, reg, rotate_left, imm);
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
     * Record the lazy-flags state the gadget left. After a shift by CL it is
     * in env, which the gadget wrote. An env_cc_op gadget writes its state
     * to env as well.
     */
    if (by_cl) {
        assume_cc_op(s, CC_OP_DYNAMIC);
    } else if (facts->kind == RCG_KIND_BT) {
        if (kept_eflags) {
            /* As prepare_update_cf() chooses: ADCOX when cc_src2 holds OF. */
            set_cc_op(s, s->cc_op == CC_OP_ADOX || s->cc_op == CC_OP_ADCOX
                         ? CC_OP_ADCOX : CC_OP_ADCX);
        } else {
            /* cc_dst is kept, so the width is the earlier state's. */
            set_cc_op(s, facts->cc_op + cc_op_size(s->cc_op));
        }
    } else if (facts->cc_op >= 0) {
        CCOp cc_op = facts->cc_op + (facts->by_width ? ot : 0);

        if (facts->env_cc_op) {
            assume_cc_op(s, cc_op);
        } else {
            set_cc_op(s, cc_op);
        }
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
