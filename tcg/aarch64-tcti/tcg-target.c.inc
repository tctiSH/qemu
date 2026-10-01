/*
 * Tiny Code Threaded Intepreter for QEMU
 *
 * Copyright (c) 2021 Kate Temkin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


// Rich disassembly is nice in theory, but it's -slow-.
//#define TCTI_GADGET_RICH_DISASSEMBLY

#define TCTI_GADGET_IMMEDIATE_ARRAY_LEN 64

// Specify the shape of the stack our runtime will use.
#define TCG_TARGET_CALL_STACK_OFFSET    0
#define TCG_TARGET_STACK_ALIGN          16
#define TCG_TARGET_CALL_ARG_I32         TCG_CALL_ARG_NORMAL
#define TCG_TARGET_CALL_ARG_I64         TCG_CALL_ARG_NORMAL
#define TCG_TARGET_CALL_ARG_I128        TCG_CALL_ARG_NORMAL
#define TCG_TARGET_CALL_RET_I128        TCG_CALL_RET_NORMAL

#include "tcg/tcg-ldst.h"
#include "tcg/tcg-inline-fp.h"
#include "tcti-gadget-defs.h"

// Grab our gadget headers.
#include "tcti_gadgets.h"

/* Enable TCTI assertions only when debugging TCG (and without NDEBUG defined).
 * Without assertions, the interpreter runs much faster. */
#if defined(CONFIG_DEBUG_TCG)
# define tcti_assert(cond) assert(cond)
#else
# define tcti_assert(cond) ((void)0)
#endif

/*
 * The shapes of the generated gadget tables: one gadget per register (or
 * immediate) in each dimension.
 */
typedef const void *TCTIGadget1[TCG_TARGET_GP_REGS];
typedef const void *TCTIGadget2[TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS];
typedef const void *TCTIGadget3[TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS];

/* A gadget family per condition, named by its AArch64 condition code. */
#define TCTI_COND_TABLE(prefix) {           \
    [TCG_COND_EQ]  = &prefix ## eq,         \
    [TCG_COND_NE]  = &prefix ## ne,         \
    [TCG_COND_LT]  = &prefix ## lt,         \
    [TCG_COND_GE]  = &prefix ## ge,         \
    [TCG_COND_LE]  = &prefix ## le,         \
    [TCG_COND_GT]  = &prefix ## gt,         \
    [TCG_COND_LTU] = &prefix ## lo,         \
    [TCG_COND_GEU] = &prefix ## hs,         \
    [TCG_COND_LEU] = &prefix ## ls,         \
    [TCG_COND_GTU] = &prefix ## hi,         \
}

/********************************
 *  TCG Constraints Definitions *
 ********************************/

/*
 * Only the vector ops, and our own, are described here; the scalar ops carry
 * their constraints in their TCGOutOp, below.
 */
static TCGConstraintSetIndex
tcg_target_op_def(TCGOpcode op, TCGType type, unsigned flags)
{
    switch (op) {

    //
    // Vector ops.
    //
    case INDEX_op_add_vec:
    case INDEX_op_sub_vec:
    case INDEX_op_mul_vec:
    case INDEX_op_xor_vec:
    case INDEX_op_ssadd_vec:
    case INDEX_op_sssub_vec:
    case INDEX_op_usadd_vec:
    case INDEX_op_ussub_vec:
    case INDEX_op_smax_vec:
    case INDEX_op_smin_vec:
    case INDEX_op_umax_vec:
    case INDEX_op_umin_vec:
    case INDEX_op_shlv_vec:
    case INDEX_op_shrv_vec:
    case INDEX_op_sarv_vec:
    case INDEX_op_aa64_sshl_vec:
        return C_O1_I2(w, w, w);
    case INDEX_op_not_vec:
    case INDEX_op_neg_vec:
    case INDEX_op_abs_vec:
    case INDEX_op_shli_vec:
    case INDEX_op_shri_vec:
    case INDEX_op_sari_vec:
        return C_O1_I1(w, w);
    case INDEX_op_ld_vec:
    case INDEX_op_dupm_vec:
        return C_O1_I1(w, r);
    case INDEX_op_st_vec:
        return C_O0_I2(w, r);
    case INDEX_op_dup_vec:
        return C_O1_I1(w, wr);
    case INDEX_op_or_vec:
    case INDEX_op_andc_vec:
        return C_O1_I2(w, w, w);
    case INDEX_op_and_vec:
    case INDEX_op_orc_vec:
        return C_O1_I2(w, w, w);
    case INDEX_op_cmp_vec:
        return C_O1_I2(w, w, w);
    case INDEX_op_bitsel_vec:
        return C_O1_I3(w, w, w, w);
    case INDEX_op_aa64_sli_vec:
        return C_O1_I2(w, 0, w);

    default:
        return C_NotImplemented;
    }
}

static const int tcg_target_reg_alloc_order[] = {

    // General purpose registers, in preference-of-allocation order.
    TCG_REG_R8,
    TCG_REG_R9,
    TCG_REG_R10,
    TCG_REG_R11,
    TCG_REG_R12,
    TCG_REG_R13,
    TCG_REG_R0,
    TCG_REG_R1,
    TCG_REG_R2,
    TCG_REG_R3,
    TCG_REG_R4,
    TCG_REG_R5,
    TCG_REG_R6,
    TCG_REG_R7,

    // Note: we do not allocate R14 or R15, as they're used for our
    // special-purpose values.

    // We'll use the high 16 vector register; avoiding the call-saved lower ones.
    TCG_REG_V16, TCG_REG_V17, TCG_REG_V18, TCG_REG_V19,
    TCG_REG_V20, TCG_REG_V21, TCG_REG_V22, TCG_REG_V23,
    TCG_REG_V24, TCG_REG_V25, TCG_REG_V26, TCG_REG_V27,
    TCG_REG_V28, TCG_REG_V29, TCG_REG_V30, TCG_REG_V31,
};

/*
 * All eight of the AArch64 argument registers. The call gadget passes nothing
 * on the stack -- it calls the helper with whatever sp it has -- so an
 * argument TCG decided to pass there never reached the helper, and was
 * written over the host stack besides; see tcg_qemu_tb_exec(). With eight,
 * no helper needs the stack: none takes more than MAX_CALL_IARGS (7).
 */
static const int tcg_target_call_iarg_regs[] = {
    TCG_REG_R0,
    TCG_REG_R1,
    TCG_REG_R2,
    TCG_REG_R3,
    TCG_REG_R4,
    TCG_REG_R5,
    TCG_REG_R6,
    TCG_REG_R7,
};

QEMU_BUILD_BUG_ON(ARRAY_SIZE(tcg_target_call_iarg_regs) < MAX_CALL_IARGS);

static TCGReg tcg_target_call_oarg_reg(TCGCallReturnKind kind, int slot)
{
    tcg_debug_assert(kind == TCG_CALL_RET_NORMAL);
    tcg_debug_assert(slot >= 0 && slot < 128 / TCG_TARGET_REG_BITS);
    return TCG_REG_R0 + slot;
}

#ifdef CONFIG_DEBUG_TCG
static const char *const tcg_target_reg_names[TCG_TARGET_NB_REGS] = {
    "r00", "r01", "r02", "r03", "r04", "r05", "r06", "r07",
    "r08", "r09", "r10", "r11", "r12", "r13", "r14", "r15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "fp",  "lr",  "sp",
    "v00", "v01", "v02", "v03", "v04", "v05", "v06", "v07",
    "v08", "v09", "v10", "v11", "v12", "v13", "v14", "v15",
    "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
    "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
};
#endif

/*************************
 *  TCG Emitter Helpers  *
 *************************/

static bool patch_reloc(tcg_insn_unit *code_ptr, int type,
                        intptr_t value, intptr_t addend)
{
    /* tcg_out_reloc always uses the same type, addend. */
    tcg_debug_assert(type == sizeof(tcg_target_long));
    tcg_debug_assert(addend == 0);
    tcg_debug_assert(value != 0);
    tcg_patch64(code_ptr, value);
    return true;
}

/* Write value (native size). */
static void tcg_out_immediate(TCGContext *s, tcg_target_ulong v)
{
    tcg_out64(s, v);
}

void tb_target_set_jmp_target(const TranslationBlock *tb, int n,
                              uintptr_t jmp_rx, uintptr_t jmp_rw)
{
    /* Get a pointer to our immediate, which exists after a single pointer. */
    uintptr_t immediate_addr = jmp_rw;
    uintptr_t addr = tb->jmp_target_addr[n];

    /* Patch it to be match our target address. */
    qatomic_set((uint64_t *)immediate_addr, addr);
}


/**
 * TCTI Emmiter Helpers
 */


/* Write gadget pointer. */
static void tcg_out_gadget(TCGContext *s, const void *gadget)
{
    tcg_out_immediate(s, (tcg_target_ulong)gadget);
}

/* Write gadget pointer, plus 64b immediate. */
static void tcg_out_imm64_gadget(TCGContext *s, const void *gadget, tcg_target_ulong immediate)
{
    tcg_out_gadget(s, gadget);
    tcg_out64(s, immediate);
}


/* Write gadget pointer (one register). */
static void tcg_out_unary_gadget(TCGContext *s, const void *gadget_base[TCG_TARGET_GP_REGS], unsigned reg0)
{
    tcg_out_gadget(s, gadget_base[reg0]);
}


/* Write gadget pointer (two registers). */
static void tcg_out_binary_gadget(TCGContext *s, const void *gadget_base[TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS], unsigned reg0, unsigned reg1)
{
    tcg_out_gadget(s, gadget_base[reg0][reg1]);
}


/* Write gadget pointer (three registers). */
static void tcg_out_ternary_gadget(TCGContext *s, const void *gadget_base[TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS], unsigned reg0, unsigned reg1, unsigned reg2)
{
    tcg_out_gadget(s, gadget_base[reg0][reg1][reg2]);
}


/* Write gadget pointer (three registers, last is immediate value). */
static void tcg_out_ternary_immediate_gadget(TCGContext *s, const void *gadget_base[TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS][TCTI_GADGET_IMMEDIATE_ARRAY_LEN], unsigned reg0, unsigned reg1, unsigned reg2)
{
    tcg_out_gadget(s, gadget_base[reg0][reg1][reg2]);
}

/***************************
 *  TCG Scalar Operations  *
 ***************************/

/**
 * Version of our LDST generator that defers to more optimized gadgets selectively.
 */
static void tcg_out_ldst_gadget_inner(TCGContext *s,
    const void *gadget_base[TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS],
    const void *gadget_pos_imm[TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS][TCTI_GADGET_IMMEDIATE_ARRAY_LEN],
    const void *gadget_shifted_imm[TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS][TCTI_GADGET_IMMEDIATE_ARRAY_LEN],
    const void *gadget_neg_imm[TCG_TARGET_GP_REGS][TCG_TARGET_GP_REGS][TCTI_GADGET_IMMEDIATE_ARRAY_LEN],
    unsigned reg0, unsigned reg1, uint32_t offset)
{
    int64_t extended_offset = (int32_t)offset;
    bool is_negative = (extended_offset < 0);

    // Optimal case: we have a gadget that handles our specific offset, so we don't need to encode
    // an immediate. This saves us a bunch of speed. :)

    // We handle positive and negative gadgets separately, in order to allow for asymmetrical
    // collections of pre-made gadgets.
    if (!is_negative)
    {
        uint64_t shifted_offset = (extended_offset >> 3);
        bool aligned_to_8B = ((extended_offset & 0b111) == 0);

        bool have_optimized_gadget = (extended_offset < TCTI_GADGET_IMMEDIATE_ARRAY_LEN);
        bool have_shifted_gadget   = (shifted_offset  < TCTI_GADGET_IMMEDIATE_ARRAY_LEN);

        // More optimal case: we have a gadget that directly encodes the argument.
        if (have_optimized_gadget) {
            tcg_out_gadget(s, gadget_pos_imm[reg0][reg1][extended_offset]);
            return;
        }

        // Special case: it's frequent to have low-numbered positive offsets that are aligned
        // to 16B boundaries
        else if(aligned_to_8B && have_shifted_gadget) {
            tcg_out_gadget(s, gadget_shifted_imm[reg0][reg1][shifted_offset]);
            return;
        }
    }
    else {
        uint64_t negated_offset = -(extended_offset);

        // More optimal case: we have a gadget that directly encodes the argument.
        if (negated_offset < TCTI_GADGET_IMMEDIATE_ARRAY_LEN) {
            tcg_out_gadget(s, gadget_neg_imm[reg0][reg1][negated_offset]);
            return;
        }
    }

    // Less optimal case: we don't have a gadget specifically for this. Emit the general case immediate.
    tcg_out_binary_gadget(s, gadget_base, reg0, reg1);
    tcg_out64(s, extended_offset); //tcg_out32(s, offset);
}

/* Shorthand for the above, that prevents us from having to specify the name three times. */
#define tcg_out_ldst_gadget(s, name, a, b, c) \
    tcg_out_ldst_gadget_inner(s, name, \
        name ## _imm,  \
        name ## _sh8_imm,  \
        name ## _neg_imm, \
    a, b, c)



/* Write label. */
static void tcti_out_label(TCGContext *s, TCGLabel *label)
{
    if (label->has_value) {
        tcg_out64(s, label->u.value);
        tcg_debug_assert(label->u.value);
    } else {
        tcg_out_reloc(s, s->code_ptr, sizeof(tcg_target_ulong), label, 0);
        s->code_ptr += sizeof(tcg_target_ulong);
    }
}


/* Register to register move using ORR (shifted register with no shift). */
static void tcg_out_movr(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rm)
{
    switch(ext) {
        case TCG_TYPE_I32:
            tcg_out_binary_gadget(s, gadget_mov_i32, rd, rm);
            break;

        case TCG_TYPE_I64:
            tcg_out_binary_gadget(s, gadget_mov_i64, rd, rm);
            break;

        default:
            g_assert_not_reached();

    }
}


static void tcti_note_env_arg(TCGContext *s, tcg_insn_unit *start,
                              TCGReg reg, intptr_t offset);
static void tcti_rewind(TCGContext *s, tcg_insn_unit *to);

/*
 * Whether a label is bound in (start, end]: a fusion that rewinds to start
 * would leave a branch to it pointing into the fused gadget's stream.
 */
static bool tcti_label_within(TCGContext *s, const tcg_insn_unit *start,
                              const tcg_insn_unit *end)
{
    TCGLabel *l;

    QSIMPLEQ_FOREACH(l, &s->labels, next) {
        if (l->has_value && l->u.value_ptr > start && l->u.value_ptr <= end) {
            return true;
        }
    }
    return false;
}

static bool tcg_out_mov(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    TCGReg w_ret = (ret - TCG_REG_V16);
    TCGReg w_arg = (arg - TCG_REG_V16);

    if (ret == arg) {
        return true;
    }

    switch (type) {
    case TCG_TYPE_I32:
    case TCG_TYPE_I64:

        // If this is a GP to GP register mov, issue our standard MOV.
        if (ret < 32 && arg < 32) {
            tcg_insn_unit *start = s->code_ptr;

            tcg_out_movr(s, type, ret, arg);
            if (type == TCG_TYPE_I64 && arg == TCG_AREG0) {
                tcti_note_env_arg(s, start, ret, 0);
            }
            break;
        }
        // If this is a vector register to GP, issue a UMOV.
        else if (ret < 32) {
            void *gadget = (type == TCG_TYPE_I32) ? gadget_umov_s0 : gadget_umov_d0;
            tcg_out_binary_gadget(s, gadget, ret, w_arg);
            break;
        }

        // If this is a GP to vector move, insert the vealue using INS.
        else if (arg < 32) {
            void *gadget = (type == TCG_TYPE_I32) ? gadget_ins_s0 : gadget_ins_d0;
            tcg_out_binary_gadget(s, gadget, w_ret, arg);
            break;
        }
        /* FALLTHRU */

    case TCG_TYPE_V64:
        tcg_debug_assert(ret >= 32 && arg >= 32);
        tcg_out_ternary_gadget(s, gadget_or_d, w_ret, w_arg, w_arg);
        break;

    case TCG_TYPE_V128:
        tcg_debug_assert(ret >= 32 && arg >= 32);
        tcg_out_ternary_gadget(s, gadget_or_q, w_ret, w_arg, w_arg);
        break;

    default:
        g_assert_not_reached();
    }
    return true;
}



/*
 * The last 32-bit constant put in a register, so that a store of it to env
 * straight after can join it in an sti32_env gadget. Per thread, as
 * translation is.
 */
static __thread struct {
    tcg_insn_unit *start, *end;
    TCGReg reg;
    uint32_t value;
} tcti_last_movi32;

static void tcg_out_movi_i32_gadget(TCGContext *s, TCGReg t0,
                                    tcg_target_long arg);

static void tcg_out_movi_i32(TCGContext *s, TCGReg t0, tcg_target_long arg)
{
    tcg_insn_unit *start = s->code_ptr;

    tcg_out_movi_i32_gadget(s, t0, arg);
    tcti_last_movi32.start = start;
    tcti_last_movi32.end = s->code_ptr;
    tcti_last_movi32.reg = t0;
    tcti_last_movi32.value = arg;
}

static void tcg_out_movi_i32_gadget(TCGContext *s, TCGReg t0,
                                    tcg_target_long arg)
{
    bool is_negative = (arg < 0);

    // We handle positive and negative gadgets separately, in order to allow for asymmetrical
    // collections of pre-made gadgets.
    if (!is_negative)
    {
        // More optimal case: we have a gadget that directly encodes the argument.
        if (arg < ARRAY_SIZE(gadget_movi_imm_i32[t0])) {
            tcg_out_gadget(s, gadget_movi_imm_i32[t0][arg]);
            return;
        }
    }

    // Emit the mov and its immediate.
    tcg_out_unary_gadget(s, gadget_movi_i32, t0);
    tcg_out64(s, arg); // TODO: make 32b?
}


static void tcg_out_movi_i64(TCGContext *s, TCGReg t0, tcg_target_long arg)
{
    uint8_t is_negative = arg < 0;

    // We handle positive and negative gadgets separately, in order to allow for asymmetrical
    // collections of pre-made gadgets.
    if (!is_negative)
    {
        // More optimal case: we have a gadget that directly encodes the argument.
        if (arg < ARRAY_SIZE(gadget_movi_imm_i64[t0])) {
            tcg_out_gadget(s, gadget_movi_imm_i64[t0][arg]);
            return;
        }
    }

    // TODO: optimize the negative case, too?

    // Less optimal case: emit the mov and its immediate.
    tcg_out_unary_gadget(s, gadget_movi_i64, t0);
    tcg_out64(s, arg);
}


/**
 * Generate an immediate-to-register MOV.
 */
static void tcg_out_movi(TCGContext *s, TCGType type, TCGReg t0, tcg_target_long arg)
{
    if (type == TCG_TYPE_I32) {
        tcg_out_movi_i32(s, t0, arg);
    } else {
        tcg_out_movi_i64(s, t0, arg);
    }
}

static void tcg_out_ext8s(TCGContext *s, TCGType type, TCGReg rd, TCGReg rs)
{
    switch (type) {
    case TCG_TYPE_I32:
        tcg_out_binary_gadget(s, gadget_ext8s_i32, rd, rs);
        break;
    case TCG_TYPE_I64:
        tcg_out_binary_gadget(s, gadget_ext8s_i64, rd, rs);
        break;
    default:
        g_assert_not_reached();
    }
}

static void tcg_out_ext8u(TCGContext *s, TCGReg rd, TCGReg rs)
{
    tcg_out_binary_gadget(s, gadget_ext8u, rd, rs);
}

static void tcg_out_ext16s(TCGContext *s, TCGType type, TCGReg rd, TCGReg rs)
{
    switch (type) {
    case TCG_TYPE_I32:
        tcg_out_binary_gadget(s, gadget_ext16s_i32, rd, rs);
        break;
    case TCG_TYPE_I64:
        tcg_out_binary_gadget(s, gadget_ext16s_i64, rd, rs);
        break;
    default:
        g_assert_not_reached();
    }
}

static void tcg_out_ext16u(TCGContext *s, TCGReg rd, TCGReg rs)
{
    tcg_out_binary_gadget(s, gadget_ext16u, rd, rs);
}

static void tcg_out_ext32s(TCGContext *s, TCGReg rd, TCGReg rs)
{
    tcg_out_binary_gadget(s, gadget_ext32s_i64, rd, rs);
}

static void tcg_out_ext32u(TCGContext *s, TCGReg rd, TCGReg rs)
{
    tcg_out_binary_gadget(s, gadget_ext32u_i64, rd, rs);
}

static void tcg_out_exts_i32_i64(TCGContext *s, TCGReg rd, TCGReg rs)
{
    tcg_out_ext32s(s, rd, rs);
}

static void tcg_out_extu_i32_i64(TCGContext *s, TCGReg rd, TCGReg rs)
{
    tcg_out_ext32u(s, rd, rs);
}

static void tcg_out_extrl_i64_i32(TCGContext *s, TCGReg rd, TCGReg rs)
{
    tcg_out_binary_gadget(s, gadget_extrl, rd, rs);
}

static bool tcg_out_xchg(TCGContext *s, TCGType type, TCGReg r1, TCGReg r2)
{
    return false;
}

static void tcg_out_addi_ptr(TCGContext *s, TCGReg rd, TCGReg rs,
                              tcg_target_long imm)
{
    /* This function is only used for passing structs by reference. */
    g_assert_not_reached();
}

/**
 * Generate a CALL.
 */
/*
 * The gadgets just emitted that set an argument register to env plus a
 * constant (a mov from env, or an addi to it), for tcg_out_call() to fold
 * into a call_envN gadget. Each entry is contiguous with the one before;
 * anything else emitted in between restarts the log. Per thread, as
 * translation is.
 */
#define TCTI_ENV_ARGS 8

static __thread struct {
    int n;
    struct {
        tcg_insn_unit *start, *end;
        TCGReg reg;
        intptr_t offset;
    } e[TCTI_ENV_ARGS];
} tcti_env_args;

static void tcti_note_env_arg(TCGContext *s, tcg_insn_unit *start,
                              TCGReg reg, intptr_t offset)
{
    int n = tcti_env_args.n;

    if (reg >= TCTI_ENV_ARGS) {
        tcti_env_args.n = 0;
        return;
    }
    if (n == 0 || tcti_env_args.e[n - 1].end != start || n == TCTI_ENV_ARGS) {
        n = 0;
    }
    tcti_env_args.e[n].start = start;
    tcti_env_args.e[n].end = s->code_ptr;
    tcti_env_args.e[n].reg = reg;
    tcti_env_args.e[n].offset = offset;
    tcti_env_args.n = n + 1;
}

static const void *const tcti_call_env[TCTI_ENV_ARGS] = {
    gadget_call_env0, gadget_call_env1, gadget_call_env2, gadget_call_env3,
    gadget_call_env4, gadget_call_env5, gadget_call_env6, gadget_call_env7,
};

/*
 * The inline float gadgets (tcg/tcg-inline-fp.h), indexed [env][op][form]:
 * "_env" computes the arguments from env and stream offsets.
 */
#define TCTI_INLINE_FP_FORMS(prefix, op) {                                  \
    gadget_ ## prefix ## _ ## op ## _ps16, gadget_ ## prefix ## _ ## op ## _ps32, \
    gadget_ ## prefix ## _ ## op ## _pd16, gadget_ ## prefix ## _ ## op ## _pd32, \
    gadget_ ## prefix ## _ ## op ## _ss, gadget_ ## prefix ## _ ## op ## _sd, \
}
#define TCTI_INLINE_FP_OPS(prefix) {                                        \
    [TCG_INLINE_FP_ADD] = TCTI_INLINE_FP_FORMS(prefix, add),                \
    [TCG_INLINE_FP_SUB] = TCTI_INLINE_FP_FORMS(prefix, sub),                \
    [TCG_INLINE_FP_MUL] = TCTI_INLINE_FP_FORMS(prefix, mul),                \
    [TCG_INLINE_FP_DIV] = TCTI_INLINE_FP_FORMS(prefix, div),                \
    [TCG_INLINE_FP_MIN] = TCTI_INLINE_FP_FORMS(prefix, min),                \
    [TCG_INLINE_FP_MAX] = TCTI_INLINE_FP_FORMS(prefix, max),                \
}

static const void *const tcti_inline_fp[2][TCG_INLINE_FP_MAX + 1][6] = {
    TCTI_INLINE_FP_OPS(inline_fp), TCTI_INLINE_FP_OPS(inline_fp_env),
};

/* The form's index in tcti_inline_fp: ps16, ps32, pd16, pd32, ss, sd. */
static int tcti_inline_fp_form(const TCGInlineFP *fp)
{
    bool dbl = fp->esize == MO_64;

    switch (fp->bytes) {
    case 16:
        return dbl ? 2 : 0;
    case 32:
        return dbl ? 3 : 1;
    default:
        return dbl ? 5 : 4;
    }
}

static void tcg_out_call(TCGContext *s, const tcg_insn_unit *func,
                         const TCGHelperInfo *info)
{
    const TCGInlineFP *fp = tcg_inline_fp(func);

    int n = tcti_env_args.n, first = -1, top = -1;
    intptr_t offset[TCTI_ENV_ARGS];
    unsigned seen = 0;

    /*
     * Walk back over the env-argument gadgets directly before this call,
     * for the longest run that sets exactly R0..Rtop, each once. The fused
     * gadget does the same writes, so folding them changes nothing else.
     */
    if (n && tcti_env_args.e[n - 1].end == s->code_ptr) {
        for (int i = n - 1; i >= 0; i--) {
            unsigned bit = 1u << tcti_env_args.e[i].reg;

            if ((seen & bit) ||
                (i < n - 1 &&
                 tcti_env_args.e[i].end != tcti_env_args.e[i + 1].start)) {
                break;
            }
            seen |= bit;
            offset[tcti_env_args.e[i].reg] = tcti_env_args.e[i].offset;
            if ((seen & (seen + 1)) == 0) {
                first = i;
                top = ctz32(~seen) - 1;
            }
        }
    }
    tcti_env_args.n = 0;

    if (first >= 0 &&
        tcti_label_within(s, tcti_env_args.e[first].start, s->code_ptr)) {
        first = -1;
    }

    /*
     * A registered float helper: its gadget does the operation itself when
     * it can. With all four arguments env plus constants, it computes them
     * too, in place of the gadgets that did.
     */
    if (fp) {
        bool env = first >= 0 && top == 3;

        if (env) {
            tcti_rewind(s, tcti_env_args.e[first].start);
        }
        tcg_out_gadget(s, tcti_inline_fp[env][fp->op][tcti_inline_fp_form(fp)]);
        tcg_out64(s, (uintptr_t)func);
        if (env) {
            for (int r = 0; r <= top; r++) {
                tcg_out64(s, offset[r]);
            }
        }
        tcg_out64(s, fp->status_ofs);
        tcg_out64(s, fp->status_mask | (uint64_t)fp->status_want << 32);
        return;
    }

    if (first >= 0) {
        tcti_rewind(s, tcti_env_args.e[first].start);
        tcg_out_gadget(s, tcti_call_env[top]);
        tcg_out64(s, (uintptr_t)func);
        for (int r = 0; r <= top; r++) {
            tcg_out64(s, offset[r]);
        }
        return;
    }

    tcg_out_gadget(s, gadget_call);
    tcg_out64(s, (uintptr_t)func);
}

/**
 * Generates LD instructions.
 */
/*
 * The last 32-bit load from env emitted, so tgen_brcondi() can fuse it with
 * a following "branch if negative" into tb_exit_check: that pair starts
 * every TB. Per thread, as translation is.
 */
static __thread struct {
    tcg_insn_unit *start, *end;
    TCGReg reg;
    intptr_t offset;
} tcti_last_env_ld32;

/*
 * The last 64-bit load or store between a register and env emitted, so that
 * the next one, to the slot beside it, can join it in an ldp_env or stp_env
 * gadget: guest registers are adjacent in env, and are synced and reloaded
 * in runs. Per thread, as translation is.
 */
static __thread struct {
    tcg_insn_unit *start, *end;
    TCGReg reg;
    intptr_t offset;
    bool is_st;
} tcti_last_env_ldst64;

/*
 * A 64-bit load from env that an add or and of an immediate directly
 * followed: if the result is stored straight back to the same slot, the
 * three become one addi_env or andi_env gadget. Per thread, as translation is.
 */
static __thread struct {
    tcg_insn_unit *start, *end;
    const void *(*gadgets)[TCG_TARGET_GP_REGS];
    TCGReg dst, src;
    intptr_t offset;
    tcg_target_long imm;
} tcti_env_rmw;

/* Called after an i64 op dst = src op imm, emitted from start. */
static void tcti_note_env_rmw(TCGContext *s, tcg_insn_unit *start,
                              const void *(*gadgets)[TCG_TARGET_GP_REGS],
                              TCGReg dst, TCGReg src, tcg_target_long imm)
{
    typeof(tcti_last_env_ldst64) *ld = &tcti_last_env_ldst64;

    tcti_env_rmw.end = NULL;
    if (ld->end == start && !ld->is_st && ld->reg == src) {
        tcti_env_rmw.start = ld->start;
        tcti_env_rmw.end = s->code_ptr;
        tcti_env_rmw.gadgets = gadgets;
        tcti_env_rmw.dst = dst;
        tcti_env_rmw.src = src;
        tcti_env_rmw.offset = ld->offset;
        tcti_env_rmw.imm = imm;
    }
}

/*
 * Every fusion moves code_ptr back to the start of what it replaces. A note
 * of something emitted before could then match code_ptr by chance, so each
 * rewind forgets them all; fusing is never needed for correctness.
 */
static void tcti_rewind(TCGContext *s, tcg_insn_unit *to)
{
    s->code_ptr = to;
    tcti_env_args.n = 0;
    tcti_last_env_ld32.end = NULL;
    tcti_last_env_ldst64.end = NULL;
    tcti_env_rmw.end = NULL;
    tcti_last_movi32.end = NULL;
}

/*
 * Emit a 64-bit load or store of reg at env + offset, joining it to the one
 * just before if that was the same kind to the neighbouring slot.
 */
static void tcti_out_env_ldst64(TCGContext *s, bool is_st, TCGReg reg,
                                intptr_t offset)
{
    typeof(tcti_last_env_ldst64) *last = &tcti_last_env_ldst64;
    typeof(tcti_env_rmw) *rmw = &tcti_env_rmw;
    tcg_insn_unit *start = s->code_ptr;

    if (is_st && rmw->end == s->code_ptr && rmw->dst == reg &&
        rmw->offset == offset &&
        !tcti_label_within(s, rmw->start, s->code_ptr)) {
        TCGReg dst = rmw->dst, src = rmw->src;
        const void *(*gadgets)[TCG_TARGET_GP_REGS] = rmw->gadgets;
        tcg_target_long imm = rmw->imm;

        tcti_rewind(s, rmw->start);
        tcg_out_gadget(s, gadgets[dst][src]);
        tcg_out64(s, offset);
        tcg_out64(s, imm);
        return;
    }
    if (last->end == s->code_ptr && last->is_st == is_st &&
        (last->offset + 8 == offset || offset + 8 == last->offset) &&
        (is_st || last->reg != reg) &&
        !tcti_label_within(s, last->start, s->code_ptr)) {
        bool up = last->offset < offset;
        TCGReg lo = up ? last->reg : reg, hi = up ? reg : last->reg;
        intptr_t lo_offset = up ? last->offset : offset;

        tcti_rewind(s, last->start);    /* and a pair takes no third */
        tcg_out_gadget(s, (is_st ? gadget_stp_env : gadget_ldp_env)[lo][hi]);
        tcg_out64(s, lo_offset);
        return;
    }
    /* tcg_out_ldst_gadget() pastes the gadget's name: one call each. */
    if (is_st) {
        tcg_out_ldst_gadget(s, gadget_st_i64, reg, TCG_AREG0, offset);
    } else {
        tcg_out_ldst_gadget(s, gadget_ld_i64, reg, TCG_AREG0, offset);
    }
    last->start = start;
    last->end = s->code_ptr;
    last->reg = reg;
    last->offset = offset;
    last->is_st = is_st;
}

static void tcg_out_ld(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg1,
                       intptr_t arg2)
{
    if (type == TCG_TYPE_I64 && arg1 == TCG_AREG0) {
        tcti_out_env_ldst64(s, false, ret, arg2);
        return;
    }
    if (type == TCG_TYPE_I32 && arg1 == TCG_AREG0) {
        tcti_last_env_ld32.start = s->code_ptr;
        tcg_out_ldst_gadget(s, gadget_ld32u, ret, arg1, arg2);
        tcti_last_env_ld32.end = s->code_ptr;
        tcti_last_env_ld32.reg = ret;
        tcti_last_env_ld32.offset = arg2;
        return;
    }
    if (type == TCG_TYPE_I32) {
        tcg_out_ldst_gadget(s, gadget_ld32u, ret, arg1, arg2);
    } else {
        tcg_out_ldst_gadget(s, gadget_ld_i64, ret, arg1, arg2);
    }
}

static void tcg_out_exit_tb(TCGContext *s, uintptr_t arg)
{
    // Emit a simple gadget with a known return code.
    tcg_out_imm64_gadget(s, gadget_exit_tb, arg);
}

static void tcg_out_goto_tb(TCGContext *s, int which)
{
    // If we're using a direct jump, we'll emit a "relocation" that can be usd
    // to patch our gadget stream with the target address, later.

    // Emit our gadget.
    tcg_out_gadget(s, gadget_br);

    // Place our current instruction into our "relocation table", so it can
    // be patched once we know where the branch will target...
    s->gen_tb->jmp_insn_offset[which] = tcg_current_code_size(s);

    // ... and emit our relocation.
    tcg_out64(s, which);

    set_jmp_reset_offset(s, which);
}

/*
 * Continue with the gadget stream at a0 without leaving it: the next TB's,
 * or tcg_code_gen_epilogue's, which exits to the main loop.
 */
static void tcg_out_goto_ptr(TCGContext *s, TCGReg a0)
{
    tcg_out_unary_gadget(s, gadget_goto_ptr, a0);
}

/* Simple branch. */
static void tcg_out_br(TCGContext *s, TCGLabel *l)
{
    tcg_out_gadget(s, gadget_br);
    tcti_out_label(s, l);
}

/* Memory barriers. */
static void tcg_out_mb(TCGContext *s, unsigned a0)
{
    static void* sync[] = {
        [0 ... TCG_MO_ALL]            = gadget_mb_all,
        [TCG_MO_ST_ST]                = gadget_mb_st,
        [TCG_MO_LD_LD]                = gadget_mb_ld,
        [TCG_MO_LD_ST]                = gadget_mb_ld,
        [TCG_MO_LD_ST | TCG_MO_LD_LD] = gadget_mb_ld,
    };
    tcg_out_gadget(s, sync[a0 & TCG_MO_ALL]);
}

/*
 * There are no carry gadgets, so the carry ops are C_NotImplemented and
 * tcg-op.c never asks for these.
 */
static void tcg_out_set_carry(TCGContext *s)
{
    g_assert_not_reached();
}

static void tcg_out_set_borrow(TCGContext *s)
{
    g_assert_not_reached();
}

/* We expect to use a 7-bit scaled negative offset from ENV.  */
#define MIN_TLB_MASK_TABLE_OFS  -512

/*
 * Arithmetic and logic. Every one of these is a single gadget per register
 * combination, with an _i32 and an _i64 flavour where the width matters.
 */

#define TCTI_BINARY_OP(name, gadget32, gadget64)                            \
    static void tgen_##name(TCGContext *s, TCGType type,                    \
                            TCGReg a0, TCGReg a1, TCGReg a2)                \
    {                                                                       \
        tcg_out_ternary_gadget(s, type == TCG_TYPE_I32 ? gadget32 : gadget64, \
                               a0, a1, a2);                                 \
    }                                                                       \
    static const TCGOutOpBinary outop_##name = {                            \
        .base.static_constraint = C_O1_I2(r, r, r),                         \
        .out_rrr = tgen_##name,                                             \
    };

/*
 * The same, where the second operand may also be a constant: the gadget
 * takes it from the stream, so it costs no movi (and no register).
 */
#define TCTI_BINARY_OP_I(name, gadget32, gadget64, gadgeti32, gadgeti64)    \
    static void tgen_##name(TCGContext *s, TCGType type,                    \
                            TCGReg a0, TCGReg a1, TCGReg a2)                \
    {                                                                       \
        tcg_out_ternary_gadget(s, type == TCG_TYPE_I32 ? gadget32 : gadget64, \
                               a0, a1, a2);                                 \
    }                                                                       \
    static void tgen_##name##i(TCGContext *s, TCGType type,                 \
                               TCGReg a0, TCGReg a1, tcg_target_long a2)    \
    {                                                                       \
        tcg_insn_unit *start = s->code_ptr;                                 \
        tcg_out_binary_gadget(s, type == TCG_TYPE_I32 ? gadgeti32 : gadgeti64, \
                              a0, a1);                                      \
        tcg_out64(s, a2);                                                   \
        if (gadgeti64 == gadget_addi_i64 && type == TCG_TYPE_I64 &&         \
            a1 == TCG_AREG0) {                                              \
            tcti_note_env_arg(s, start, a0, a2);                            \
        }                                                                   \
        if (type == TCG_TYPE_I64 && (gadgeti64 == gadget_addi_i64 ||        \
                                     gadgeti64 == gadget_andi_i64)) {       \
            tcti_note_env_rmw(s, start, gadgeti64 == gadget_addi_i64 ?      \
                              gadget_addi_env : gadget_andi_env, a0, a1, a2); \
        }                                                                   \
    }                                                                       \
    static const TCGOutOpBinary outop_##name = {                            \
        .base.static_constraint = C_O1_I2(r, r, ri),                        \
        .out_rrr = tgen_##name,                                             \
        .out_rri = tgen_##name##i,                                          \
    };

TCTI_BINARY_OP_I(add, gadget_add_i32, gadget_add_i64,
                 gadget_addi_i32, gadget_addi_i64)
TCTI_BINARY_OP_I(and, gadget_and_i32, gadget_and_i64,
                 gadget_andi_i32, gadget_andi_i64)
TCTI_BINARY_OP(andc, gadget_andc_i32, gadget_andc_i64)
TCTI_BINARY_OP(clz,  gadget_clz_i32,  gadget_clz_i64)
TCTI_BINARY_OP(ctz,  gadget_ctz_i32,  gadget_ctz_i64)
TCTI_BINARY_OP(divs, gadget_div_i32,  gadget_div_i64)
TCTI_BINARY_OP(divu, gadget_divu_i32, gadget_divu_i64)
TCTI_BINARY_OP(eqv,  gadget_eqv_i32,  gadget_eqv_i64)
TCTI_BINARY_OP(mul,  gadget_mul_i32,  gadget_mul_i64)
TCTI_BINARY_OP(nand, gadget_nand_i32, gadget_nand_i64)
TCTI_BINARY_OP(nor,  gadget_nor_i32,  gadget_nor_i64)
TCTI_BINARY_OP_I(or, gadget_or_i32, gadget_or_i64,
                 gadget_ori_i32, gadget_ori_i64)
TCTI_BINARY_OP(orc,  gadget_orc_i32,  gadget_orc_i64)
TCTI_BINARY_OP(rems, gadget_rem_i32,  gadget_rem_i64)
TCTI_BINARY_OP(remu, gadget_remu_i32, gadget_remu_i64)
TCTI_BINARY_OP(rotl, gadget_rotl_i32, gadget_rotl_i64)
TCTI_BINARY_OP(rotr, gadget_rotr_i32, gadget_rotr_i64)
TCTI_BINARY_OP_I(sar, gadget_sar_i32, gadget_sar_i64,
                 gadget_sari_i32, gadget_sari_i64)
TCTI_BINARY_OP_I(shl, gadget_shl_i32, gadget_shl_i64,
                 gadget_shli_i32, gadget_shli_i64)
TCTI_BINARY_OP_I(shr, gadget_shr_i32, gadget_shr_i64,
                 gadget_shri_i32, gadget_shri_i64)
TCTI_BINARY_OP_I(xor, gadget_xor_i32, gadget_xor_i64,
                 gadget_xori_i32, gadget_xori_i64)

#undef TCTI_BINARY_OP
#undef TCTI_BINARY_OP_I

static void tgen_sub(TCGContext *s, TCGType type,
                     TCGReg a0, TCGReg a1, TCGReg a2)
{
    tcg_out_ternary_gadget(s, type == TCG_TYPE_I32 ? gadget_sub_i32 : gadget_sub_i64,
                           a0, a1, a2);
}

static const TCGOutOpSubtract outop_sub = {
    .base.static_constraint = C_O1_I2(r, r, r),
    .out_rrr = tgen_sub,
};

static void tgen_neg(TCGContext *s, TCGType type, TCGReg a0, TCGReg a1)
{
    tcg_out_binary_gadget(s, type == TCG_TYPE_I32 ? gadget_neg_i32 : gadget_neg_i64,
                          a0, a1);
}

static const TCGOutOpUnary outop_neg = {
    .base.static_constraint = C_O1_I1(r, r),
    .out_rr = tgen_neg,
};

static void tgen_not(TCGContext *s, TCGType type, TCGReg a0, TCGReg a1)
{
    tcg_out_binary_gadget(s, type == TCG_TYPE_I32 ? gadget_not_i32 : gadget_not_i64,
                          a0, a1);
}

static const TCGOutOpUnary outop_not = {
    .base.static_constraint = C_O1_I1(r, r),
    .out_rr = tgen_not,
};

/* Ops we have no gadgets for, and which tcg-op.c expands for us. */
static const TCGOutOpBinary outop_addco = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpAddSubCarry outop_addci = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpBinary outop_addcio = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpAddSubCarry outop_subbo = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpAddSubCarry outop_subbi = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpAddSubCarry outop_subbio = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpUnary outop_ctpop = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpDeposit outop_deposit = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpDivRem outop_divs2 = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpDivRem outop_divu2 = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpExtract2 outop_extract2 = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpMul2 outop_muls2 = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpBinary outop_mulsh = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpMul2 outop_mulu2 = {
    .base.static_constraint = C_NotImplemented,
};

static const TCGOutOpBinary outop_muluh = {
    .base.static_constraint = C_NotImplemented,
};

/*
 * Extensions. TCG_TARGET_extract_valid() only admits the 8-, 16- and 32-bit
 * cases at offset zero, each of which is one gadget.
 */
static void tgen_extract(TCGContext *s, TCGType type, TCGReg a0, TCGReg a1,
                         unsigned ofs, unsigned len)
{
    tcg_debug_assert(ofs == 0);
    switch (len) {
    case 8:
        tcg_out_ext8u(s, a0, a1);
        break;
    case 16:
        tcg_out_ext16u(s, a0, a1);
        break;
    case 32:
        tcg_out_ext32u(s, a0, a1);
        break;
    default:
        g_assert_not_reached();
    }
}

static const TCGOutOpExtract outop_extract = {
    .base.static_constraint = C_O1_I1(r, r),
    .out_rr = tgen_extract,
};

static void tgen_sextract(TCGContext *s, TCGType type, TCGReg a0, TCGReg a1,
                          unsigned ofs, unsigned len)
{
    tcg_debug_assert(ofs == 0);
    switch (len) {
    case 8:
        tcg_out_ext8s(s, type, a0, a1);
        break;
    case 16:
        tcg_out_ext16s(s, type, a0, a1);
        break;
    case 32:
        tcg_out_ext32s(s, a0, a1);
        break;
    default:
        g_assert_not_reached();
    }
}

static const TCGOutOpExtract outop_sextract = {
    .base.static_constraint = C_O1_I1(r, r),
    .out_rr = tgen_sextract,
};

static void tgen_extrh_i64_i32(TCGContext *s, TCGType t, TCGReg a0, TCGReg a1)
{
    tcg_out_binary_gadget(s, gadget_extrh, a0, a1);
}

static const TCGOutOpUnary outop_extrh_i64_i32 = {
    .base.static_constraint = C_O1_I1(r, r),
    .out_rr = tgen_extrh_i64_i32,
};

/* Byte swaps. The gadgets leave the result zero-extended. */
static void tgen_bswap16(TCGContext *s, TCGType type,
                         TCGReg a0, TCGReg a1, unsigned flags)
{
    tcg_out_binary_gadget(s, gadget_bswap16, a0, a1);
    if (flags & TCG_BSWAP_OS) {
        tcg_out_ext16s(s, type, a0, a0);
    }
}

static const TCGOutOpBswap outop_bswap16 = {
    .base.static_constraint = C_O1_I1(r, r),
    .out_rr = tgen_bswap16,
};

static void tgen_bswap32(TCGContext *s, TCGType type,
                         TCGReg a0, TCGReg a1, unsigned flags)
{
    tcg_out_binary_gadget(s, gadget_bswap32, a0, a1);
    if (type == TCG_TYPE_I64 && (flags & TCG_BSWAP_OS)) {
        tcg_out_ext32s(s, a0, a0);
    }
}

static const TCGOutOpBswap outop_bswap32 = {
    .base.static_constraint = C_O1_I1(r, r),
    .out_rr = tgen_bswap32,
};

static void tgen_bswap64(TCGContext *s, TCGType type, TCGReg a0, TCGReg a1)
{
    tcg_out_binary_gadget(s, gadget_bswap64, a0, a1);
}

static const TCGOutOpUnary outop_bswap64 = {
    .base.static_constraint = C_O1_I1(r, r),
    .out_rr = tgen_bswap64,
};

/*
 * Comparisons.
 */

static TCTIGadget3 *const tcti_setcond_i32[16] = TCTI_COND_TABLE(gadget_setcond_i32_);
static TCTIGadget3 *const tcti_setcond_i64[16] = TCTI_COND_TABLE(gadget_setcond_i64_);
static TCTIGadget3 *const tcti_brcond_i32[16] = TCTI_COND_TABLE(gadget_brcond_i32_);
static TCTIGadget3 *const tcti_brcond_i64[16] = TCTI_COND_TABLE(gadget_brcond_i64_);
static TCTIGadget2 *const tcti_brcondi_i32[16] = TCTI_COND_TABLE(gadget_brcondi_i32_);
static TCTIGadget2 *const tcti_brcondi_i64[16] = TCTI_COND_TABLE(gadget_brcondi_i64_);
static TCTIGadget3 *const tcti_csel[16] = TCTI_COND_TABLE(gadget_csel_);
static TCTIGadget1 *const tcti_csetm_i32[16] = TCTI_COND_TABLE(gadget_csetm_i32_);
static TCTIGadget1 *const tcti_csetm_i64[16] = TCTI_COND_TABLE(gadget_csetm_i64_);

/* Set the flags, for a csel or csetm gadget to consume. */
static void tcti_out_cmp(TCGContext *s, TCGType type, TCGReg a1, TCGReg a2)
{
    tcg_out_binary_gadget(s, type == TCG_TYPE_I32 ? gadget_cmp_i32 : gadget_cmp_i64,
                          a1, a2);
}

static void tgen_setcond(TCGContext *s, TCGType type, TCGCond cond,
                         TCGReg dest, TCGReg arg1, TCGReg arg2)
{
    TCTIGadget3 *gadget = (type == TCG_TYPE_I32 ? tcti_setcond_i32 : tcti_setcond_i64)[cond];

    tcg_debug_assert(gadget);
    tcg_out_gadget(s, (*gadget)[dest][arg1][arg2]);
}

static const TCGOutOpSetcond outop_setcond = {
    .base.static_constraint = C_O1_I2(r, r, r),
    .out_rrr = tgen_setcond,
};

static void tgen_negsetcond(TCGContext *s, TCGType type, TCGCond cond,
                            TCGReg dest, TCGReg arg1, TCGReg arg2)
{
    TCTIGadget1 *gadget = (type == TCG_TYPE_I32 ? tcti_csetm_i32 : tcti_csetm_i64)[cond];

    tcg_debug_assert(gadget);
    tcti_out_cmp(s, type, arg1, arg2);
    tcg_out_gadget(s, (*gadget)[dest]);
}

static const TCGOutOpSetcond outop_negsetcond = {
    .base.static_constraint = C_O1_I2(r, r, r),
    .out_rrr = tgen_negsetcond,
};

static void tgen_brcond(TCGContext *s, TCGType type, TCGCond cond,
                        TCGReg arg0, TCGReg arg1, TCGLabel *l)
{
    static uint8_t last_brcond = 0;
    TCTIGadget3 *gadget = (type == TCG_TYPE_I32 ? tcti_brcond_i32 : tcti_brcond_i64)[cond];

    tcg_debug_assert(gadget);

    // We'll select the which branch to used based on a cycling counter.
    // This means we'll pick one of 16 identical brconds. Spreading this out
    // helps the processor's branch prediction be less "squished", as not every
    // branch is going throuh the same instruction.
    tcg_out_gadget(s, (*gadget)[last_brcond][arg0][arg1]);
    last_brcond = (last_brcond + 1) % TCG_TARGET_GP_REGS;

    // Branch target immediate.
    tcti_out_label(s, l);
}

/* The same against a constant, which the gadget reads before the target. */
static void tgen_brcondi(TCGContext *s, TCGType type, TCGCond cond,
                         TCGReg arg0, tcg_target_long arg1, TCGLabel *l)
{
    static uint8_t last_brcond = 0;
    TCTIGadget2 *gadget = (type == TCG_TYPE_I32 ? tcti_brcondi_i32 : tcti_brcondi_i64)[cond];

    tcg_debug_assert(gadget);

    /*
     * A load of this register from env just before: the TB-start exit
     * check. The fused gadget does the load too, so the register holds the
     * same value either way.
     */
    if (type == TCG_TYPE_I32 && cond == TCG_COND_LT && arg1 == 0 &&
        tcti_last_env_ld32.end == s->code_ptr &&
        tcti_last_env_ld32.reg == arg0 &&
        !tcti_label_within(s, tcti_last_env_ld32.start, s->code_ptr)) {
        intptr_t offset = tcti_last_env_ld32.offset;

        tcti_rewind(s, tcti_last_env_ld32.start);
        tcg_out_unary_gadget(s, gadget_tb_exit_check, arg0);
        tcg_out64(s, offset);
        tcti_out_label(s, l);
        return;
    }

    tcg_out_gadget(s, (*gadget)[last_brcond][arg0]);
    last_brcond = (last_brcond + 1) % TCG_TARGET_GP_REGS;
    tcg_out64(s, arg1);
    tcti_out_label(s, l);
}

static const TCGOutOpBrcond outop_brcond = {
    .base.static_constraint = C_O0_I2(r, ri),
    .out_rr = tgen_brcond,
    .out_ri = tgen_brcondi,
};

/*
 * movcond is mandatory since 10.1. Five registers are too many for one
 * gadget per combination, so it is a compare, which only sets the flags,
 * and a csel that reads them.
 */
static void tgen_movcond(TCGContext *s, TCGType type, TCGCond cond,
                         TCGReg ret, TCGReg c1, TCGArg c2, bool const_c2,
                         TCGArg vt, bool const_vt, TCGArg vf, bool const_vf)
{
    TCTIGadget3 *gadget = tcti_csel[cond];

    tcg_debug_assert(gadget);
    tcg_debug_assert(!const_c2 && !const_vt && !const_vf);
    tcti_out_cmp(s, type, c1, c2);
    tcg_out_gadget(s, (*gadget)[ret][vt][vf]);
}

static const TCGOutOpMovcond outop_movcond = {
    .base.static_constraint = C_O1_I4(r, r, r, r, r),
    .out = tgen_movcond,
};

/*
 * Host loads and stores, relative to a register.
 */

static void tgen_ld8u(TCGContext *s, TCGType type, TCGReg dest,
                      TCGReg base, intptr_t offset)
{
    tcg_out_ldst_gadget(s, gadget_ld8u, dest, base, offset);
}

static const TCGOutOpLoad outop_ld8u = {
    .base.static_constraint = C_O1_I1(r, r),
    .out = tgen_ld8u,
};

static void tgen_ld8s(TCGContext *s, TCGType type, TCGReg dest,
                      TCGReg base, intptr_t offset)
{
    if (type == TCG_TYPE_I32) {
        tcg_out_ldst_gadget(s, gadget_ld8s_i32, dest, base, offset);
    } else {
        tcg_out_ldst_gadget(s, gadget_ld8s_i64, dest, base, offset);
    }
}

static const TCGOutOpLoad outop_ld8s = {
    .base.static_constraint = C_O1_I1(r, r),
    .out = tgen_ld8s,
};

static void tgen_ld16u(TCGContext *s, TCGType type, TCGReg dest,
                       TCGReg base, intptr_t offset)
{
    tcg_out_ldst_gadget(s, gadget_ld16u, dest, base, offset);
}

static const TCGOutOpLoad outop_ld16u = {
    .base.static_constraint = C_O1_I1(r, r),
    .out = tgen_ld16u,
};

static void tgen_ld16s(TCGContext *s, TCGType type, TCGReg dest,
                       TCGReg base, intptr_t offset)
{
    if (type == TCG_TYPE_I32) {
        tcg_out_ldst_gadget(s, gadget_ld16s_i32, dest, base, offset);
    } else {
        tcg_out_ldst_gadget(s, gadget_ld16s_i64, dest, base, offset);
    }
}

static const TCGOutOpLoad outop_ld16s = {
    .base.static_constraint = C_O1_I1(r, r),
    .out = tgen_ld16s,
};

static void tgen_ld32u(TCGContext *s, TCGType type, TCGReg dest,
                       TCGReg base, intptr_t offset)
{
    tcg_out_ldst_gadget(s, gadget_ld32u, dest, base, offset);
}

static const TCGOutOpLoad outop_ld32u = {
    .base.static_constraint = C_O1_I1(r, r),
    .out = tgen_ld32u,
};

static void tgen_ld32s(TCGContext *s, TCGType type, TCGReg dest,
                       TCGReg base, intptr_t offset)
{
    tcg_out_ldst_gadget(s, gadget_ld32s_i64, dest, base, offset);
}

static const TCGOutOpLoad outop_ld32s = {
    .base.static_constraint = C_O1_I1(r, r),
    .out = tgen_ld32s,
};

static void tgen_st8(TCGContext *s, TCGType type, TCGReg data,
                     TCGReg base, intptr_t offset)
{
    tcg_out_ldst_gadget(s, gadget_st8, data, base, offset);
}

static const TCGOutOpStore outop_st8 = {
    .base.static_constraint = C_O0_I2(r, r),
    .out_r = tgen_st8,
};

static void tgen_st16(TCGContext *s, TCGType type, TCGReg data,
                      TCGReg base, intptr_t offset)
{
    tcg_out_ldst_gadget(s, gadget_st16, data, base, offset);
}

static const TCGOutOpStore outop_st16 = {
    .base.static_constraint = C_O0_I2(r, r),
    .out_r = tgen_st16,
};

/**
 * Generate immediate stores.
 */
static void tcg_out_st(TCGContext *s, TCGType type, TCGReg arg, TCGReg arg1,
                       intptr_t arg2)
{
    if (type == TCG_TYPE_I64 && arg1 == TCG_AREG0) {
        tcti_out_env_ldst64(s, true, arg, arg2);
        return;
    }
    if (type == TCG_TYPE_I32 && arg1 == TCG_AREG0 &&
        tcti_last_movi32.end == s->code_ptr && tcti_last_movi32.reg == arg &&
        arg2 == (int32_t)arg2 &&
        !tcti_label_within(s, tcti_last_movi32.start, s->code_ptr)) {
        uint32_t value = tcti_last_movi32.value;

        tcti_rewind(s, tcti_last_movi32.start);
        tcg_out_unary_gadget(s, gadget_movi_st32_env, arg);
        tcg_out64(s, value | (uint64_t)arg2 << 32);
        return;
    }
    if (type == TCG_TYPE_I32) {
        tcg_out_ldst_gadget(s, gadget_st_i32, arg, arg1, arg2);
    } else {
        tcg_out_ldst_gadget(s, gadget_st_i64, arg, arg1, arg2);
    }
}

static const TCGOutOpStore outop_st = {
    .base.static_constraint = C_O0_I2(r, r),
    .out_r = tcg_out_st,
};

/* Constants stored to env, as x86's cc_op is when a TB leaves. */
static inline bool tcg_out_sti(TCGContext *s, TCGType type, TCGArg val,
                               TCGReg base, intptr_t ofs)
{
    if (base != TCG_AREG0 || ofs != (int32_t)ofs) {
        return false;
    }
    switch (type) {
    case TCG_TYPE_I32:
        tcg_out_gadget(s, gadget_sti32_env);
        tcg_out64(s, (uint32_t)val | (uint64_t)ofs << 32);
        return true;
    case TCG_TYPE_I64:
        tcg_out_gadget(s, gadget_sti64_env);
        tcg_out64(s, ofs);
        tcg_out64(s, val);
        return true;
    default:
        return false;
    }
}

/*
 * Guest loads and stores.
 *
 * Each is one gadget, which looks the address up in the softmmu TLB itself and
 * calls into C only on a miss. That lookup reads the CPUTLBDescFast at a fixed
 * offset from env, so there is a gadget per MMU index; see
 * tcti-gadget-defs.h. Indices without one, and pages other than 4K, take a
 * gadget that always calls the C helper.
 *
 * The "aligned" gadgets check only the page of the first byte, which is right
 * for single bytes. Everything else uses the "unaligned" ones, which also
 * check the page of the last byte, so that an access never straddles into a
 * page the TLB entry does not describe.
 *
 * Every gadget is followed by the MemOpIdx, which the slow path passes to the
 * helper and the fast path steps over.
 */

#define TCTI_BY_MMU_IDX(prefix, suffix) {                                   \
    &prefix ## idx0 ## suffix, &prefix ## idx1 ## suffix,                   \
    &prefix ## idx2 ## suffix, &prefix ## idx3 ## suffix,                   \
    &prefix ## idx4 ## suffix, &prefix ## idx5 ## suffix,                   \
}

QEMU_BUILD_BUG_ON(TCTI_TLB_FAST_MMU_INDICES != 6);

#define TCTI_QEMU_LD_BY_SIZE(variant, type) {                               \
    [MO_UB] = TCTI_BY_MMU_IDX(gadget_qemu_ld_ub_   ## variant ## _, _ ## type), \
    [MO_SB] = TCTI_BY_MMU_IDX(gadget_qemu_ld_sb_   ## variant ## _, _ ## type), \
    [MO_UW] = TCTI_BY_MMU_IDX(gadget_qemu_ld_leuw_ ## variant ## _, _ ## type), \
    [MO_SW] = TCTI_BY_MMU_IDX(gadget_qemu_ld_lesw_ ## variant ## _, _ ## type), \
    [MO_UL] = TCTI_BY_MMU_IDX(gadget_qemu_ld_leul_ ## variant ## _, _ ## type), \
    [MO_SL] = TCTI_BY_MMU_IDX(gadget_qemu_ld_lesl_ ## variant ## _, _ ## type), \
    [MO_UQ] = TCTI_BY_MMU_IDX(gadget_qemu_ld_leq_  ## variant ## _, _ ## type), \
}

#define TCTI_QEMU_LD_SLOW(variant, type) {                                  \
    [MO_UB] = &gadget_qemu_ld_ub_   ## variant ## _any_ ## type,            \
    [MO_SB] = &gadget_qemu_ld_sb_   ## variant ## _any_ ## type,            \
    [MO_UW] = &gadget_qemu_ld_leuw_ ## variant ## _any_ ## type,            \
    [MO_SW] = &gadget_qemu_ld_lesw_ ## variant ## _any_ ## type,            \
    [MO_UL] = &gadget_qemu_ld_leul_ ## variant ## _any_ ## type,            \
    [MO_SL] = &gadget_qemu_ld_lesl_ ## variant ## _any_ ## type,            \
    [MO_UQ] = &gadget_qemu_ld_leq_  ## variant ## _any_ ## type,            \
}

#define TCTI_QEMU_ST_BY_SIZE(variant, type) {                               \
    [MO_8]  = TCTI_BY_MMU_IDX(gadget_qemu_st_ub_   ## variant ## _, _ ## type), \
    [MO_16] = TCTI_BY_MMU_IDX(gadget_qemu_st_leuw_ ## variant ## _, _ ## type), \
    [MO_32] = TCTI_BY_MMU_IDX(gadget_qemu_st_leul_ ## variant ## _, _ ## type), \
    [MO_64] = TCTI_BY_MMU_IDX(gadget_qemu_st_leq_  ## variant ## _, _ ## type), \
}

#define TCTI_QEMU_ST_SLOW(variant, type) {                                  \
    [MO_8]  = &gadget_qemu_st_ub_   ## variant ## _any_ ## type,            \
    [MO_16] = &gadget_qemu_st_leuw_ ## variant ## _any_ ## type,            \
    [MO_32] = &gadget_qemu_st_leul_ ## variant ## _any_ ## type,            \
    [MO_64] = &gadget_qemu_st_leq_  ## variant ## _any_ ## type,            \
}

/*
 * The "_ord" gadgets are the ordered ones, for tcg_ldst_ordered(): LDAPR and
 * STLR on the fast path, which then also sends an access that crosses a
 * 16-byte boundary to the slow path, and a barrier around the helper's plain
 * access on the slow path. They take the place of a barrier gadget before
 * every access.
 */

/* Indexed [is_ordered][is_aligned][is_i64][memop & MO_SSIZE][mmu_idx]. */
static TCTIGadget2 *const
tcti_qemu_ld_fast[2][2][2][MO_SSIZE + 1][TCTI_TLB_FAST_MMU_INDICES] = {
    {
        { TCTI_QEMU_LD_BY_SIZE(unaligned, i32), TCTI_QEMU_LD_BY_SIZE(unaligned, i64) },
        { TCTI_QEMU_LD_BY_SIZE(aligned, i32),   TCTI_QEMU_LD_BY_SIZE(aligned, i64) },
    },
    {
        { TCTI_QEMU_LD_BY_SIZE(unaligned_ord, i32), TCTI_QEMU_LD_BY_SIZE(unaligned_ord, i64) },
        { TCTI_QEMU_LD_BY_SIZE(aligned_ord, i32),   TCTI_QEMU_LD_BY_SIZE(aligned_ord, i64) },
    },
};

/* Indexed [is_ordered][is_i64][memop & MO_SSIZE]. */
static TCTIGadget2 *const tcti_qemu_ld_slow[2][2][MO_SSIZE + 1] = {
    { TCTI_QEMU_LD_SLOW(slowpath, i32),     TCTI_QEMU_LD_SLOW(slowpath, i64) },
    { TCTI_QEMU_LD_SLOW(slowpath_ord, i32), TCTI_QEMU_LD_SLOW(slowpath_ord, i64) },
};

/* Indexed [is_ordered][is_aligned][is_i64][memop & MO_SIZE][mmu_idx]. */
static TCTIGadget2 *const
tcti_qemu_st_fast[2][2][2][MO_64 + 1][TCTI_TLB_FAST_MMU_INDICES] = {
    {
        { TCTI_QEMU_ST_BY_SIZE(unaligned, i32), TCTI_QEMU_ST_BY_SIZE(unaligned, i64) },
        { TCTI_QEMU_ST_BY_SIZE(aligned, i32),   TCTI_QEMU_ST_BY_SIZE(aligned, i64) },
    },
    {
        { TCTI_QEMU_ST_BY_SIZE(unaligned_ord, i32), TCTI_QEMU_ST_BY_SIZE(unaligned_ord, i64) },
        { TCTI_QEMU_ST_BY_SIZE(aligned_ord, i32),   TCTI_QEMU_ST_BY_SIZE(aligned_ord, i64) },
    },
};

/* Indexed [is_ordered][is_i64][memop & MO_SIZE]. */
static TCTIGadget2 *const tcti_qemu_st_slow[2][2][MO_64 + 1] = {
    { TCTI_QEMU_ST_SLOW(slowpath, i32),     TCTI_QEMU_ST_SLOW(slowpath, i64) },
    { TCTI_QEMU_ST_SLOW(slowpath_ord, i32), TCTI_QEMU_ST_SLOW(slowpath_ord, i64) },
};

/*
 * Whether a TLB fast-path gadget can serve this access. The gadgets hard-code
 * 4K pages and 32-byte TLB entries in their index and comparison arithmetic.
 */
static bool tcti_has_fast_path(TCGContext *s, unsigned mmu_idx)
{
    if (mmu_idx >= TCTI_TLB_FAST_MMU_INDICES ||
        TARGET_PAGE_BITS != 12 || CPU_TLB_ENTRY_BITS != 5) {
        return false;
    }
    tcg_debug_assert(tlb_mask_table_ofs(s, mmu_idx) == TCTI_TLB_FAST_OFS(mmu_idx));
    return true;
}

static void tgen_qemu_ld(TCGContext *s, TCGType type, TCGReg data,
                         TCGReg addr, MemOpIdx oi)
{
    MemOp opc = get_memop(oi);
    unsigned mmu_idx = get_mmuidx(oi);
    bool is_i64 = (type == TCG_TYPE_I64);
    bool ordered = tcg_ldst_ordered(s);
    TCTIGadget2 *gadget;

    /* tcg_target_has_memory_bswap() says no, so TCG swaps separately. */
    tcg_debug_assert(!(opc & MO_BSWAP));

    if (tcti_has_fast_path(s, mmu_idx)) {
        bool is_aligned = (opc & MO_SIZE) == MO_8;
        gadget = tcti_qemu_ld_fast[ordered][is_aligned][is_i64][opc & MO_SSIZE][mmu_idx];
    } else {
        gadget = tcti_qemu_ld_slow[ordered][is_i64][opc & MO_SSIZE];
    }
    tcg_debug_assert(gadget);

    tcg_out_gadget(s, (*gadget)[data][addr]);
    tcg_out64(s, oi);
}

static const TCGOutOpQemuLdSt outop_qemu_ld = {
    .base.static_constraint = C_O1_I1(r, r),
    .out = tgen_qemu_ld,
};

/*
 * The 128-bit gadgets: one per address register, for each fast-path MMU
 * index and alignment check (none, 16 or 32 bytes), and a slow path.
 */
#define TCTI_I128_BY_MMU_IDX(op, a) {                                         \
    &gadget_qemu_ ## op ## _a ## a ## _idx0,                                 \
    &gadget_qemu_ ## op ## _a ## a ## _idx1,                                 \
    &gadget_qemu_ ## op ## _a ## a ## _idx2,                                 \
    &gadget_qemu_ ## op ## _a ## a ## _idx3,                                 \
    &gadget_qemu_ ## op ## _a ## a ## _idx4,                                 \
    &gadget_qemu_ ## op ## _a ## a ## _idx5,                                 \
}

typedef const void *TCTIGadgetI128[TCG_TARGET_GP_REGS];

/* Indexed [is_ordered][is_ld][alignment check][mmu_idx]; "_ord" as above. */
static TCTIGadgetI128 *const
tcti_qemu_i128_fast[2][2][3][TCTI_TLB_FAST_MMU_INDICES] = {
    {
        { TCTI_I128_BY_MMU_IDX(st_i128, 0), TCTI_I128_BY_MMU_IDX(st_i128, 16),
          TCTI_I128_BY_MMU_IDX(st_i128, 32) },
        { TCTI_I128_BY_MMU_IDX(ld_i128, 0), TCTI_I128_BY_MMU_IDX(ld_i128, 16),
          TCTI_I128_BY_MMU_IDX(ld_i128, 32) },
    },
    {
        { TCTI_I128_BY_MMU_IDX(st_i128_ord, 0), TCTI_I128_BY_MMU_IDX(st_i128_ord, 16),
          TCTI_I128_BY_MMU_IDX(st_i128_ord, 32) },
        { TCTI_I128_BY_MMU_IDX(ld_i128_ord, 0), TCTI_I128_BY_MMU_IDX(ld_i128_ord, 16),
          TCTI_I128_BY_MMU_IDX(ld_i128_ord, 32) },
    },
};

/* Indexed [is_ordered][is_ld]. */
static TCTIGadgetI128 *const tcti_qemu_i128_slow[2][2] = {
    { &gadget_qemu_st_i128_a0_any,     &gadget_qemu_ld_i128_a0_any },
    { &gadget_qemu_st_i128_ord_a0_any, &gadget_qemu_ld_i128_ord_a0_any },
};

static void tcti_out_qemu_ldst_i128(TCGContext *s, bool is_ld, TCGReg addr,
                                    MemOpIdx oi)
{
    MemOp opc = get_memop(oi);
    unsigned mmu_idx = get_mmuidx(oi);
    unsigned a_bits = memop_alignment_bits(opc);
    bool ordered = tcg_ldst_ordered(s);
    TCTIGadgetI128 *gadget;

    tcg_debug_assert(!(opc & MO_BSWAP));

    /* An alignment the gadget does not check is left to the slow path. */
    if (tcti_has_fast_path(s, mmu_idx) && a_bits <= 5) {
        int check = a_bits == 0 ? 0 : a_bits <= 4 ? 1 : 2;
        gadget = tcti_qemu_i128_fast[ordered][is_ld][check][mmu_idx];
    } else {
        gadget = tcti_qemu_i128_slow[ordered][is_ld];
    }
    tcg_out_gadget(s, (*gadget)[addr]);
    tcg_out64(s, oi);
}

static void tgen_qemu_ld2(TCGContext *s, TCGType type, TCGReg datalo,
                          TCGReg datahi, TCGReg addr, MemOpIdx oi)
{
    tcg_debug_assert(type == TCG_TYPE_I128);
    tcg_debug_assert(datalo == TCG_REG_R0 && datahi == TCG_REG_R1);
    tcti_out_qemu_ldst_i128(s, true, addr, oi);
}

static const TCGOutOpQemuLdSt2 outop_qemu_ld2 = {
    .base.static_constraint = C_O2_I1(a, b, r),
    .out = tgen_qemu_ld2,
};

static void tgen_qemu_st(TCGContext *s, TCGType type, TCGReg data,
                         TCGReg addr, MemOpIdx oi)
{
    MemOp opc = get_memop(oi);
    unsigned mmu_idx = get_mmuidx(oi);
    bool is_i64 = (type == TCG_TYPE_I64);
    bool ordered = tcg_ldst_ordered(s);
    TCTIGadget2 *gadget;

    tcg_debug_assert(!(opc & MO_BSWAP));

    if (tcti_has_fast_path(s, mmu_idx)) {
        bool is_aligned = (opc & MO_SIZE) == MO_8;
        gadget = tcti_qemu_st_fast[ordered][is_aligned][is_i64][opc & MO_SIZE][mmu_idx];
    } else {
        gadget = tcti_qemu_st_slow[ordered][is_i64][opc & MO_SIZE];
    }
    tcg_debug_assert(gadget);

    tcg_out_gadget(s, (*gadget)[data][addr]);
    tcg_out64(s, oi);
}

static const TCGOutOpQemuLdSt outop_qemu_st = {
    .base.static_constraint = C_O0_I2(r, r),
    .out = tgen_qemu_st,
};

static void tgen_qemu_st2(TCGContext *s, TCGType type, TCGReg datalo,
                          TCGReg datahi, TCGReg addr, MemOpIdx oi)
{
    tcg_debug_assert(type == TCG_TYPE_I128);
    tcg_debug_assert(datalo == TCG_REG_R2 && datahi == TCG_REG_R3);
    tcti_out_qemu_ldst_i128(s, false, addr, oi);
}

static const TCGOutOpQemuLdSt2 outop_qemu_st2 = {
    .base.static_constraint = C_O0_I3(c, d, r),
    .out = tgen_qemu_st2,
};

/* Test if a constant matches the constraint. */
static bool tcg_target_const_match(int64_t val, int ct,
                                   TCGType type, TCGCond cond, int vece)
{
    return ct & TCG_CT_CONST;
}

static void tcg_out_nop_fill(tcg_insn_unit *p, int count)
{
    memset(p, 0, sizeof(*p) * count);
}

/***************************
 *  TCG Vector Operations  *
 ***************************/

//
// Helper for emitting DUPI (immediate DUP) instructions.
//
#define tcg_out_dupi_gadget(s, name, q, rd, op, cmode, arg) \
    if (q) { \
        tcg_out_gadget(s, gadget_ ## name ## _cmode_ ## cmode ## _op ## op ## _q1[rd][arg]); \
    } else { \
        tcg_out_gadget(s, gadget_ ## name ## _cmode_ ## cmode ## _op ## op ## _q0[rd][arg]); \
    }


//
// Helpers for emitting D/Q variant instructions.
//
#define tcg_out_dq_gadget(s, name, arity, is_q, args...) \
    if (is_q) { \
        tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _q, args); \
    } else { \
        tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _d, args); \
    }

#define tcg_out_unary_dq_gadget(s, name, is_q, a) \
    tcg_out_dq_gadget(s, name, unary, is_q, a)
#define tcg_out_binary_dq_gadget(s, name, is_q, a, b) \
    tcg_out_dq_gadget(s, name, binary, is_q, a, b)
#define tcg_out_ternary_dq_gadget(s, name, is_q, a, b, c) \
    tcg_out_dq_gadget(s, name, ternary, is_q, a, b, c)


//
// Helper for emitting the gadget appropriate for a vector's size.
//
#define tcg_out_sized_vector_gadget(s, name, arity, vece, args...) \
    switch(vece) { \
        case MO_8: \
            if (type == TCG_TYPE_V64) { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _8b, args); \
            } else { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _16b, args); \
            } \
            break; \
        case MO_16: \
            if (type == TCG_TYPE_V64) { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _4h, args); \
            } else { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _8h, args); \
            } \
            break; \
        case MO_32: \
            if (type == TCG_TYPE_V64) { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _2s, args); \
            } else { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _4s, args); \
            } \
            break; \
        case MO_64: \
            if (type == TCG_TYPE_V128) { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _2d, args); \
            } \
            else { \
                g_assert_not_reached(); \
            } \
            break;  \
        default: \
            g_assert_not_reached(); \
    }
#define tcg_out_sized_vector_gadget_no64(s, name, arity, vece, args...) \
    switch(vece) { \
        case MO_8: \
            if (type == TCG_TYPE_V64) { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _8b, args); \
            } else { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _16b, args); \
            } \
            break; \
        case MO_16: \
            if (type == TCG_TYPE_V64) { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _4h, args); \
            } else { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _8h, args); \
            } \
            break; \
        case MO_32: \
            if (type == TCG_TYPE_V64) { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _2s, args); \
            } else { \
                tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _4s, args); \
            } \
            break; \
        default: \
            g_assert_not_reached(); \
    }


#define tcg_out_unary_vector_gadget(s, name, vece, a) \
    tcg_out_sized_vector_gadget(s, name, unary, vece, a)
#define tcg_out_binary_vector_gadget(s, name, vece, a, b) \
    tcg_out_sized_vector_gadget(s, name, binary, vece, a, b)
#define tcg_out_ternary_vector_gadget(s, name, vece, a, b, c) \
    tcg_out_sized_vector_gadget(s, name, ternary, vece, a, b, c)

#define tcg_out_ternary_vector_gadget_no64(s, name, vece, a, b, c) \
    tcg_out_sized_vector_gadget_no64(s, name, ternary, vece, a, b, c)


#define tcg_out_sized_gadget_with_scalar(s, name, arity, is_scalar, vece, args...) \
    if (is_scalar) { \
        tcg_out_ ## arity ## _gadget(s, gadget_ ## name ## _scalar, args); \
    } else { \
        tcg_out_sized_vector_gadget(s, name, arity, vece, args); \
    }

#define tcg_out_ternary_vector_gadget_with_scalar(s, name, is_scalar, vece, a, b, c) \
    tcg_out_sized_gadget_with_scalar(s, name, ternary, is_scalar, vece, a, b, c)

#define tcg_out_ternary_immediate_vector_gadget_with_scalar(s, name, is_scalar, vece, a, b, c) \
    tcg_out_sized_gadget_with_scalar(s, name, ternary_immediate, is_scalar, vece, a, b, c)

/* Return true if v16 is a valid 16-bit shifted immediate.  */
static bool is_shimm16(uint16_t v16, int *cmode, int *imm8)
{
    if (v16 == (v16 & 0xff)) {
        *cmode = 0x8;
        *imm8 = v16 & 0xff;
        return true;
    } else if (v16 == (v16 & 0xff00)) {
        *cmode = 0xa;
        *imm8 = v16 >> 8;
        return true;
    }
    return false;
}


/** Core vector operation emission. */
static void tcg_out_vec_op(TCGContext *s, TCGOpcode opc, unsigned vecl, unsigned vece,
    const TCGArg args[TCG_MAX_OP_ARGS], const int const_args[TCG_MAX_OP_ARGS])
{
    TCGType type = vecl + TCG_TYPE_V64;
    TCGArg r0, r1, r2, r3, w0, w1, w2, w3;

    // Typing flags for vector operations.
    bool is_v128 = (type == TCG_TYPE_V128);
    bool is_scalar = !is_v128 && (vece == MO_64);

    // Argument shortcuts.
    r0 = args[0];
    r1 = args[1];
    r2 = args[2];
    r3 = args[3];

    // Offset argument shortcuts; offset to convert register numbers to gadget numberes.
    w0 = args[0] - TCG_REG_V16;
    w1 = args[1] - TCG_REG_V16;
    w2 = args[2] - TCG_REG_V16;
    w3 = args[3] - TCG_REG_V16;

    // Argument shortcuts, as signed.
    int64_t signed_offset_arg = (int32_t)args[2];

    switch (opc) {

    // Load memory -> vector: followed by a 64-bit offset immediate
    case INDEX_op_ld_vec:
        tcg_out_binary_dq_gadget(s, ldr, is_v128, w0, r1);
        tcg_out64(s, signed_offset_arg);
        break;

    // Store memory -> vector: followed by a 64-bit offset immediate
    case INDEX_op_st_vec:
        tcg_out_binary_dq_gadget(s, str, is_v128, w0, r1);
        tcg_out64(s, signed_offset_arg);
        break;

    // Duplciate memory to all vector elements.
    case INDEX_op_dupm_vec:
        // DUPM handles normalization itself; pass arguments raw.
        tcg_out_dupm_vec(s, type, vece, r0, r1, r2);
        break;

    case INDEX_op_add_vec:
        tcg_out_ternary_vector_gadget_with_scalar(s, add, is_scalar, vece, w0, w1, w2);
        break;

    case INDEX_op_sub_vec:
        tcg_out_ternary_vector_gadget_with_scalar(s, sub, is_scalar, vece, w0, w1, w2);
        break;

    case INDEX_op_mul_vec: // optional
        tcg_out_ternary_vector_gadget_no64(s, mul, vece, w0, w1, w2);
        break;

    case INDEX_op_neg_vec: // optional
        tcg_out_binary_vector_gadget(s, neg, vece, w0, w1);
        break;

    case INDEX_op_abs_vec: // optional
        tcg_out_binary_vector_gadget(s, abs, vece, w0, w1);
        break;

    case INDEX_op_and_vec: // optional
        tcg_out_ternary_dq_gadget(s, and, is_v128, w0, w1, w2);
        break;

    case INDEX_op_or_vec:
        tcg_out_ternary_dq_gadget(s, or, is_v128, w0, w1, w2);
        break;

    case INDEX_op_andc_vec:
        tcg_out_ternary_dq_gadget(s, andc, is_v128, w0, w1, w2);
        break;

    case INDEX_op_orc_vec: // optional
        tcg_out_ternary_dq_gadget(s, orc, is_v128, w0, w1, w2);
        break;

    case INDEX_op_xor_vec:
        tcg_out_ternary_dq_gadget(s, xor, is_v128, w0, w1, w2);
        break;

    case INDEX_op_ssadd_vec:
        tcg_out_ternary_vector_gadget_with_scalar(s, ssadd, is_scalar, vece, w0, w1, w2);
        break;

    case INDEX_op_sssub_vec:
        tcg_out_ternary_vector_gadget_with_scalar(s, sssub, is_scalar, vece, w0, w1, w2);
        break;

    case INDEX_op_usadd_vec:
        tcg_out_ternary_vector_gadget_with_scalar(s, usadd, is_scalar, vece, w0, w1, w2);
        break;

    case INDEX_op_ussub_vec:
        tcg_out_ternary_vector_gadget_with_scalar(s, ussub, is_scalar, vece, w0, w1, w2);
        break;

    case INDEX_op_smax_vec:
        tcg_out_ternary_vector_gadget_no64(s, smax, vece, w0, w1, w2);
        break;

    case INDEX_op_smin_vec:
        tcg_out_ternary_vector_gadget_no64(s, smin, vece, w0, w1, w2);
        break;

    case INDEX_op_umax_vec:
        tcg_out_ternary_vector_gadget_no64(s, umax, vece, w0, w1, w2);
        break;

    case INDEX_op_umin_vec:
        tcg_out_ternary_vector_gadget_no64(s, umin, vece, w0, w1, w2);
        break;

    case INDEX_op_not_vec: // optional
        tcg_out_binary_dq_gadget(s, not, is_v128, w0, w1);
        break;

    case INDEX_op_shlv_vec:
        tcg_out_ternary_vector_gadget_with_scalar(s, shlv, is_scalar, vece, w0, w1, w2);
        break;

    case INDEX_op_aa64_sshl_vec:
        tcg_out_ternary_vector_gadget_with_scalar(s, sshl, is_scalar, vece, w0, w1, w2);
        break;

    case INDEX_op_cmp_vec:
        switch (args[3]) {
            case TCG_COND_EQ:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmeq, is_scalar, vece, w0, w1, w2);
                break;
            case TCG_COND_NE:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmeq, is_scalar, vece, w0, w1, w2);
                tcg_out_binary_dq_gadget(s, not, is_v128, w0, w0);
                break;
            case TCG_COND_GT:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmgt, is_scalar, vece, w0, w1, w2);
                break;
            case TCG_COND_LE:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmgt, is_scalar, vece, w0, w2, w1);
                break;
            case TCG_COND_GE:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmge, is_scalar, vece, w0, w1, w2);
                break;
            case TCG_COND_LT:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmge, is_scalar, vece, w0, w2, w1);
                break;
            case TCG_COND_GTU:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmhi, is_scalar, vece, w0, w1, w2);
                break;
            case TCG_COND_LEU:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmhi, is_scalar, vece, w0, w2, w1);
                break;
            case TCG_COND_GEU:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmhs, is_scalar, vece, w0, w1, w2);
                break;
            case TCG_COND_LTU:
                tcg_out_ternary_vector_gadget_with_scalar(s, cmhs, is_scalar, vece, w0, w2, w1);
                break;
            default:
                g_assert_not_reached();
        }
        break;

    case INDEX_op_bitsel_vec: // optional
    {
        if (r0 == r3) {
            tcg_out_ternary_dq_gadget(s, bit, is_v128, w0, w2, w1);
        } else if (r0 == r2) {
            tcg_out_ternary_dq_gadget(s, bif, is_v128, w0, w3, w1);
        } else {
            if (r0 != r1) {
                tcg_out_mov(s, type, r0, r1);
            }
            tcg_out_ternary_dq_gadget(s, bsl, is_v128, w0, w2, w3);
        }
        break;
    }

    /* inhibit compiler warning because we use imm as a register */
    case INDEX_op_shli_vec:
        tcg_out_ternary_immediate_vector_gadget_with_scalar(s, shl, is_scalar, vece, w0, w1, r2);
        break;
    case INDEX_op_shri_vec:
        tcg_out_ternary_immediate_vector_gadget_with_scalar(s, ushr, is_scalar, vece, w0, w1, r2 - 1);
        break;
    case INDEX_op_sari_vec:
        tcg_out_ternary_immediate_vector_gadget_with_scalar(s, sshr, is_scalar, vece, w0, w1, r2 - 1);
        break;
    case INDEX_op_aa64_sli_vec:
        tcg_out_ternary_immediate_vector_gadget_with_scalar(s, sli, is_scalar, vece, w0, w2, r3);
        break;

    case INDEX_op_mov_vec:  /* Always emitted via tcg_out_mov.  */
    case INDEX_op_dup_vec:  /* Always emitted via tcg_out_dup_vec.  */
    default:
        g_assert_not_reached();
    }
}


int tcg_can_emit_vec_op(TCGOpcode opc, TCGType type, unsigned vece)
{
    switch (opc) {
    case INDEX_op_add_vec:
    case INDEX_op_sub_vec:
    case INDEX_op_and_vec:
    case INDEX_op_or_vec:
    case INDEX_op_xor_vec:
    case INDEX_op_andc_vec:
    case INDEX_op_orc_vec:
    case INDEX_op_neg_vec:
    case INDEX_op_abs_vec:
    case INDEX_op_not_vec:
    case INDEX_op_cmp_vec:
    case INDEX_op_shli_vec:
    case INDEX_op_shri_vec:
    case INDEX_op_sari_vec:
    case INDEX_op_ssadd_vec:
    case INDEX_op_sssub_vec:
    case INDEX_op_usadd_vec:
    case INDEX_op_ussub_vec:
    case INDEX_op_shlv_vec:
    case INDEX_op_bitsel_vec:
        return 1;
    case INDEX_op_rotli_vec:
    case INDEX_op_shrv_vec:
    case INDEX_op_sarv_vec:
    case INDEX_op_rotlv_vec:
    case INDEX_op_rotrv_vec:
        return -1;
    case INDEX_op_mul_vec:
    case INDEX_op_smax_vec:
    case INDEX_op_smin_vec:
    case INDEX_op_umax_vec:
    case INDEX_op_umin_vec:
        return vece < MO_64;

    default:
        return 0;
    }
}

void tcg_expand_vec_op(TCGOpcode opc, TCGType type, unsigned vece,
                       TCGArg a0, ...)
{
    va_list va;
    TCGv_vec v0, v1, v2, t1, t2, c1;
    TCGArg a2;


    va_start(va, a0);
    v0 = temp_tcgv_vec(arg_temp(a0));
    v1 = temp_tcgv_vec(arg_temp(va_arg(va, TCGArg)));
    a2 = va_arg(va, TCGArg);
    va_end(va);

    switch (opc) {
    case INDEX_op_rotli_vec:
        t1 = tcg_temp_new_vec(type);
        tcg_gen_shri_vec(vece, t1, v1, -a2 & ((8 << vece) - 1));
        vec_gen_4(INDEX_op_aa64_sli_vec, type, vece,
                  tcgv_vec_arg(v0), tcgv_vec_arg(t1), tcgv_vec_arg(v1), a2);
        tcg_temp_free_vec(t1);
        break;

    case INDEX_op_shrv_vec:
    case INDEX_op_sarv_vec:
        /* Right shifts are negative left shifts for AArch64.  */
        v2 = temp_tcgv_vec(arg_temp(a2));
        t1 = tcg_temp_new_vec(type);
        tcg_gen_neg_vec(vece, t1, v2);
        opc = (opc == INDEX_op_shrv_vec
               ? INDEX_op_shlv_vec : INDEX_op_aa64_sshl_vec);
        vec_gen_3(opc, type, vece, tcgv_vec_arg(v0),
                  tcgv_vec_arg(v1), tcgv_vec_arg(t1));
        tcg_temp_free_vec(t1);
        break;

    case INDEX_op_rotlv_vec:
        v2 = temp_tcgv_vec(arg_temp(a2));
        t1 = tcg_temp_new_vec(type);
        c1 = tcg_constant_vec(type, vece, 8 << vece);
        tcg_gen_sub_vec(vece, t1, v2, c1);
        /* Right shifts are negative left shifts for AArch64.  */
        vec_gen_3(INDEX_op_shlv_vec, type, vece, tcgv_vec_arg(t1),
                  tcgv_vec_arg(v1), tcgv_vec_arg(t1));
        vec_gen_3(INDEX_op_shlv_vec, type, vece, tcgv_vec_arg(v0),
                  tcgv_vec_arg(v1), tcgv_vec_arg(v2));
        tcg_gen_or_vec(vece, v0, v0, t1);
        tcg_temp_free_vec(t1);
        break;

    case INDEX_op_rotrv_vec:
        v2 = temp_tcgv_vec(arg_temp(a2));
        t1 = tcg_temp_new_vec(type);
        t2 = tcg_temp_new_vec(type);
        c1 = tcg_constant_vec(type, vece, 8 << vece);
        tcg_gen_neg_vec(vece, t1, v2);
        tcg_gen_sub_vec(vece, t2, c1, v2);
        /* Right shifts are negative left shifts for AArch64.  */
        vec_gen_3(INDEX_op_shlv_vec, type, vece, tcgv_vec_arg(t1),
                  tcgv_vec_arg(v1), tcgv_vec_arg(t1));
        vec_gen_3(INDEX_op_shlv_vec, type, vece, tcgv_vec_arg(t2),
                  tcgv_vec_arg(v1), tcgv_vec_arg(t2));
        tcg_gen_or_vec(vece, v0, t1, t2);
        tcg_temp_free_vec(t1);
        tcg_temp_free_vec(t2);
        break;

    default:
        g_assert_not_reached();
    }
}


/* Generate DUPI (move immediate) vector ops. */
static bool tcg_out_optimized_dupi_vec(TCGContext *s, TCGType type, unsigned vece, TCGReg rd, int64_t v64)
{
    bool q = (type == TCG_TYPE_V128);
    int cmode, imm8, i;

    // If we're copying an 8b immediate, we implicitly have a simple gadget for this,
    // since there are only 256 possible values * 16 registers. Emit a MOVI gadget implicitly.
    if (vece == MO_8) {
        imm8 = (uint8_t)v64;
        tcg_out_dupi_gadget(s, movi, q, rd, 0, e, imm8);
        return true;
    }

    // Otherwise, if we have a value that's all 0x00 and 0xFF bytes,
    // we can use the scalar variant of MOVI (op=1, cmode=e), which handles
    // that case directly.
    for (i = imm8 = 0; i < 8; i++) {
        uint8_t byte = v64 >> (i * 8);
        if (byte == 0xff) {
            imm8 |= 1 << i;
        } else if (byte != 0) {
            goto fail_bytes;
        }
    }
    tcg_out_dupi_gadget(s, movi, q, rd, 1, e, imm8);
    return true;
 fail_bytes:

    // Handle 16B moves.
    if (vece == MO_16) {
        uint16_t v16 = v64;

        // Check to see if we have a value representable in as a MOV imm8, possibly via a shift.
        if (is_shimm16(v16, &cmode, &imm8)) {
            // Output the corret instruction CMode for either a regular MOVI (8) or a LSL8 MOVI (a).
            if (cmode == 0x8) {
                tcg_out_dupi_gadget(s, movi, q, rd, 0, 8, imm8);
            } else {
                tcg_out_dupi_gadget(s, movi, q, rd, 0, a, imm8);
            }
            return true;
        }

        // Check to see if we have a value representable in as an inverted MOV imm8, possibly via a shift.
        if (is_shimm16(~v16, &cmode, &imm8)) {
            // Output the corret instruction CMode for either a regular MOVI (8) or a LSL8 MOVI (a).
            if (cmode == 0x8) {
                tcg_out_dupi_gadget(s, mvni, q, rd, 0, 8, imm8);
            } else {
                tcg_out_dupi_gadget(s, mvni, q, rd, 0, a, imm8);
            }
            return true;
        }

        // If we can't perform either of the optimizations, we'll need to do this in two steps.
        // Normally, we'd emit a gadget for both steps, but in this case that'd result in needing -way-
        // too many gadgets. We'll emit two, instead.
        tcg_out_dupi_gadget(s, movi, q, rd, 0, 8, v16 & 0xff);
        tcg_out_dupi_gadget(s, orr,  q, rd, 0, a, v16 >> 8);
        return true;
    }

    // FIXME: implement 32B move optimizations

    return false;
}


/* Emits instructions that can load an immediate into a vector. */
static void tcg_out_dupi_vec(TCGContext *s, TCGType type, unsigned vece, TCGReg rd, int64_t v64)
{
    // Convert Rd into a simple gadget number.
    rd = rd - (TCG_REG_V16);

    // First, try to create an optimized implementation, if possible.
    if (tcg_out_optimized_dupi_vec(s, type, vece, rd, v64)) {
        return;
    }

    // If we didn't, we'll need to load the full vector from memory.
    // Emit it into our bytecode stream as an immediate; which we'll then
    // load inside the gadget.
    if (type == TCG_TYPE_V128) {
        tcg_out_unary_gadget(s, gadget_ldi_q, rd);
        tcg_out64(s, v64);
        tcg_out64(s, v64);
    } else {
        tcg_out_unary_gadget(s, gadget_ldi_d, rd);
        tcg_out64(s, v64);
    }
}


/* Emits instructions that can load a register into a vector. */
static bool tcg_out_dup_vec(TCGContext *s, TCGType type, unsigned vece, TCGReg rd, TCGReg rs)
{
    // Compute the gadget index for the relevant vector register.
    TCGReg wd = rd - (TCG_REG_V16);

    // Emit a DUP gadget to handles the operation.
    tcg_out_binary_vector_gadget(s, dup, vece, wd, rs);
    return true;
}

static bool tcg_out_dupm_vec(TCGContext *s, TCGType type, unsigned vece, TCGReg r, TCGReg base, intptr_t offset)
{
    int64_t extended_offset = (int32_t)offset;

    // Convert the register into a simple register number for our gadgets.
    r = r - TCG_REG_V16;

    // Emit a DUPM gadget...
    tcg_out_binary_vector_gadget(s, dupm, vece, r, base);

    // ... and emit its int64 immediate offset.
    tcg_out64(s, extended_offset);

    return true;
}


/********************************
 *  TCG Runtime & Platform Def  *
 *******************************/

static void tcg_target_init(TCGContext *s)
{
    /* The current code uses uint8_t for tcg operations. */
    tcg_debug_assert(tcg_op_defs_max <= UINT8_MAX);

    // Registers available for each type of operation.
    tcg_target_available_regs[TCG_TYPE_I32]  = TCG_MASK_GP_REGISTERS;
    tcg_target_available_regs[TCG_TYPE_I64]  = TCG_MASK_GP_REGISTERS;
    tcg_target_available_regs[TCG_TYPE_V64]  = TCG_MASK_VECTOR_REGISTERS;
    tcg_target_available_regs[TCG_TYPE_V128] = TCG_MASK_VECTOR_REGISTERS;

    TCGReg unclobbered_registers[] = {
        // We don't use registers R16+ in our runtime, so we'll not bother protecting them.
        TCG_REG_R16, TCG_REG_R17, TCG_REG_R18, TCG_REG_R19,
        TCG_REG_R20, TCG_REG_R21, TCG_REG_R22, TCG_REG_R23,
        TCG_REG_R24, TCG_REG_R25, TCG_REG_R26, TCG_REG_R27,
        TCG_REG_R28, TCG_REG_R29, TCG_REG_R30, TCG_REG_R31,

        // R8-R12 are host x19-x23, which C preserves (tcti-gadget-gen.py).
        TCG_REG_R8,  TCG_REG_R9,  TCG_REG_R10, TCG_REG_R11, TCG_REG_R12,

        // Per our calling convention.
        TCG_REG_V8,  TCG_REG_V9,  TCG_REG_V10, TCG_REG_V11,
        TCG_REG_V12, TCG_REG_V13, TCG_REG_V14, TCG_REG_V15,
   };

    // Specify which registers are clobbered during call.
    tcg_target_call_clobber_regs = -1ull;
    for (unsigned i = 0; i < ARRAY_SIZE(unclobbered_registers); ++i) {
        tcg_regset_reset_reg(tcg_target_call_clobber_regs, unclobbered_registers[i]);
    }

    // Specify which local registers we're reserving.
    //
    // Note that we only have to specify registers that are used in the runtime,
    // and so not e.g. the register that contains AREG0, which can never be allocated.
    s->reserved_regs = 0;
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_CALL_STACK);

    /* We use negative offsets from "sp" so that we can distinguish
       stores that might pretend to be call arguments.  */
    tcg_set_frame(s, TCG_REG_CALL_STACK, -CPU_TEMP_BUF_NLONGS * sizeof(long), CPU_TEMP_BUF_NLONGS * sizeof(long));
}

/* Generate global QEMU prologue and epilogue code. */
static inline void tcg_target_qemu_prologue(TCGContext *s)
{
    /*
     * No prologue, as we're interpreted; but goto_ptr needs an epilogue to
     * go to when helper_lookup_tb_ptr() finds no TB: a stream that returns
     * to the main loop with 0, as exit_tb(0) does.
     */
    tcg_code_gen_epilogue = tcg_splitwx_to_rx(s->code_ptr);
    tcg_out_imm64_gadget(s, gadget_exit_tb, 0);
}

static void tcg_out_tb_start(TCGContext *s)
{
    /* Nothing from a previous (or restarted) translation may be fused. */
    tcti_env_args.n = 0;
    tcti_last_env_ld32.end = NULL;
    tcti_last_env_ldst64.end = NULL;
    tcti_env_rmw.end = NULL;
    tcti_last_movi32.end = NULL;
}

/*
 * Nor across guest instructions: unwinding maps a helper's return address
 * to the instruction whose code contains it, which a fusion could move.
 */
static void tcti_insn_start(TCGContext *s)
{
    tcti_env_args.n = 0;
    tcti_last_env_ld32.end = NULL;
    tcti_last_env_ldst64.end = NULL;
    tcti_env_rmw.end = NULL;
    tcti_last_movi32.end = NULL;
}

/*
 * The qemu_ld/st gadgets do not byte-swap, so have TCG do it around them. Only
 * a big-endian access asks, which for an x86 guest means MOVBE.
 */
bool tcg_target_has_memory_bswap(MemOp memop)
{
    return false;
}

/**
 * TCTI 'interpreter' bootstrap.
 */

// Store the current return address during helper calls.
__thread uintptr_t tcti_call_return_address;

/* Dispatch the bytecode stream contained in our translation buffer. */
uintptr_t QEMU_DISABLE_CFI tcg_qemu_tb_exec(CPUArchState *env, const void *v_tb_ptr)
{
    // Create our per-CPU temporary storage.
    //
    // TCG addresses its temporaries at negative offsets from R15, and any
    // outgoing call arguments at non-negative ones, so R15 sits between the two
    // areas and both have to be ours: an argument written past the end of the
    // temporaries used to land on this function's own frame.
    long tcg_temps[CPU_TEMP_BUF_NLONGS + TCG_STATIC_CALL_ARGS_SIZE / sizeof(long)];

    uint64_t return_value = 0;
    uintptr_t sp_value    = (uintptr_t)(tcg_temps + CPU_TEMP_BUF_NLONGS);
    uintptr_t pc_mirror   = (uintptr_t)&tcti_call_return_address;

    // Ensure our target configuration hasn't changed.
    tcti_assert(TCG_AREG0 == TCG_REG_R14);
    tcti_assert(TCG_REG_CALL_STACK == TCG_REG_R15);

    asm(
        // Our threaded-dispatch prologue needs to set up things for our machine to run.
        // This means:
        //   - Set up TCG_AREG0 (R14) to point to our architectural state.
        //   - Set up TCG_REG_CALL_STACK (R15) to point to our temporary buffer.
        //   - Point x28 (our bytecode "instruction pointer") to the relevant stream address.
        "ldr x14, %[areg0]\n"
        "ldr x15, %[sp_value]\n"
        "ldr x25, %[pc_mirror]\n"
        "ldr x28, %[start_tb_ptr]\n"

        // TCG's R8-R12 live in x19-x23, which our caller expects preserved.
        // Save them here rather than list them as clobbers: with every other
        // register taken, the compiler has none left for itself. The gadgets
        // keep sp balanced, and nothing below addresses memory through it.
        "stp x19, x20, [sp, #-48]!\n"
        "stp x21, x22, [sp, #16]\n"
        "str x23,      [sp, #32]\n"

        // To start our code, we'll -call- the gadget at the first bytecode pointer.
        // Note that we call/branch-with-link, here; so our TB_EXIT gadget can RET in order
        // to return to this point when things are complete.
        "ldr x27, [x28], #8\n"
        "blr x27\n"

        "ldr x23,      [sp, #32]\n"
        "ldp x21, x22, [sp, #16]\n"
        "ldp x19, x20, [sp], #48\n"

        // Finally, we'll copy out our final return value.
        "str x0, %[return_value]\n"

        : [return_value] "=m" (return_value)

        : [areg0]        "m"  (env),
          [sp_value]     "m"  (sp_value),
          [start_tb_ptr] "m"  (v_tb_ptr),
          [pc_mirror]    "m"  (pc_mirror)

        // We touch _every_ one of the lower registers, as we use these to execute directly.
        : "x0", "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",

        // We also use x24, x26 and x27 for temporary values, x25 for the
        // return address mirror, and x28 as our bytecode pointer.
        "x24", "x25", "x26", "x27", "x28", "cc", "memory"
    );

    return return_value;
}


/**
 *  Disassembly output support.
 */
#include <dlfcn.h>


/* Disassemble TCI bytecode. */
int print_insn_tcti(bfd_vma addr, disassemble_info *info)
{

#ifdef TCTI_GADGET_RICH_DISASSEMBLY
    Dl_info symbol_info = {};
    char symbol_name[48] ;
#endif

    int status;
    uint64_t block;

    // Read the relevant pointer.
    status = info->read_memory_func(addr, (void *)&block, sizeof(block), info);
    if (status != 0) {
        info->memory_error_func(status, addr, info);
        return -1;
    }

#ifdef TCTI_GADGET_RICH_DISASSEMBLY
    // Most of our disassembly stream will be gadgets. Try to get their names, for nice output.
    dladdr((void *)block, &symbol_info);

    if(symbol_info.dli_sname != 0) {
        strncpy(symbol_name, symbol_info.dli_sname, sizeof(symbol_name));
        symbol_name[sizeof(symbol_name) - 1] = 0;
        info->fprintf_func(info->stream, "%s", symbol_name);
    } else {
        info->fprintf_func(info->stream, "%016" PRIx64, block);
    }

#else
    info->fprintf_func(info->stream, "%016" PRIx64, block);
#endif

    return sizeof(block);
}

static bool tcg_out_qemu_ld_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    g_assert_not_reached();
}

static bool tcg_out_qemu_st_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    g_assert_not_reached();
}
