/* SPDX-License-Identifier: MIT */
/*
 * The TCGOutOp that every tcg-target.c.inc defines, by opcode: for each,
 * X(opcode, type, name), where name is the backend's TCGOutOp for opcode
 * and type is the TCGOutOp subclass it must be. tcg.c builds all_outop
 * from this, adding the few it defines itself.
 */

#define TCG_TARGET_OUTOPS(X) \
    X(INDEX_op_add, TCGOutOpBinary, outop_add)                    \
    X(INDEX_op_addci, TCGOutOpAddSubCarry, outop_addci)           \
    X(INDEX_op_addcio, TCGOutOpBinary, outop_addcio)              \
    X(INDEX_op_addco, TCGOutOpBinary, outop_addco)                \
    /* addc1o is implemented with set_carry + addcio */           \
    X(INDEX_op_addc1o, TCGOutOpBinary, outop_addcio)              \
    X(INDEX_op_and, TCGOutOpBinary, outop_and)                    \
    X(INDEX_op_andc, TCGOutOpBinary, outop_andc)                  \
    X(INDEX_op_brcond, TCGOutOpBrcond, outop_brcond)              \
    X(INDEX_op_bswap16, TCGOutOpBswap, outop_bswap16)             \
    X(INDEX_op_bswap32, TCGOutOpBswap, outop_bswap32)             \
    X(INDEX_op_clz, TCGOutOpBinary, outop_clz)                    \
    X(INDEX_op_ctpop, TCGOutOpUnary, outop_ctpop)                 \
    X(INDEX_op_ctz, TCGOutOpBinary, outop_ctz)                    \
    X(INDEX_op_deposit, TCGOutOpDeposit, outop_deposit)           \
    X(INDEX_op_divs, TCGOutOpBinary, outop_divs)                  \
    X(INDEX_op_divu, TCGOutOpBinary, outop_divu)                  \
    X(INDEX_op_divs2, TCGOutOpDivRem, outop_divs2)                \
    X(INDEX_op_divu2, TCGOutOpDivRem, outop_divu2)                \
    X(INDEX_op_eqv, TCGOutOpBinary, outop_eqv)                    \
    X(INDEX_op_extract, TCGOutOpExtract, outop_extract)           \
    X(INDEX_op_extract2, TCGOutOpExtract2, outop_extract2)        \
    X(INDEX_op_ld8u, TCGOutOpLoad, outop_ld8u)                    \
    X(INDEX_op_ld8s, TCGOutOpLoad, outop_ld8s)                    \
    X(INDEX_op_ld16u, TCGOutOpLoad, outop_ld16u)                  \
    X(INDEX_op_ld16s, TCGOutOpLoad, outop_ld16s)                  \
    X(INDEX_op_movcond, TCGOutOpMovcond, outop_movcond)           \
    X(INDEX_op_mul, TCGOutOpBinary, outop_mul)                    \
    X(INDEX_op_muls2, TCGOutOpMul2, outop_muls2)                  \
    X(INDEX_op_mulsh, TCGOutOpBinary, outop_mulsh)                \
    X(INDEX_op_mulu2, TCGOutOpMul2, outop_mulu2)                  \
    X(INDEX_op_muluh, TCGOutOpBinary, outop_muluh)                \
    X(INDEX_op_nand, TCGOutOpBinary, outop_nand)                  \
    X(INDEX_op_neg, TCGOutOpUnary, outop_neg)                     \
    X(INDEX_op_negsetcond, TCGOutOpSetcond, outop_negsetcond)     \
    X(INDEX_op_nor, TCGOutOpBinary, outop_nor)                    \
    X(INDEX_op_not, TCGOutOpUnary, outop_not)                     \
    X(INDEX_op_or, TCGOutOpBinary, outop_or)                      \
    X(INDEX_op_orc, TCGOutOpBinary, outop_orc)                    \
    X(INDEX_op_qemu_ld, TCGOutOpQemuLdSt, outop_qemu_ld)          \
    X(INDEX_op_qemu_ld2, TCGOutOpQemuLdSt2, outop_qemu_ld2)       \
    X(INDEX_op_qemu_st, TCGOutOpQemuLdSt, outop_qemu_st)          \
    X(INDEX_op_qemu_st2, TCGOutOpQemuLdSt2, outop_qemu_st2)       \
    X(INDEX_op_rems, TCGOutOpBinary, outop_rems)                  \
    X(INDEX_op_remu, TCGOutOpBinary, outop_remu)                  \
    X(INDEX_op_rotl, TCGOutOpBinary, outop_rotl)                  \
    X(INDEX_op_rotr, TCGOutOpBinary, outop_rotr)                  \
    X(INDEX_op_sar, TCGOutOpBinary, outop_sar)                    \
    X(INDEX_op_setcond, TCGOutOpSetcond, outop_setcond)           \
    X(INDEX_op_sextract, TCGOutOpExtract, outop_sextract)         \
    X(INDEX_op_shl, TCGOutOpBinary, outop_shl)                    \
    X(INDEX_op_shr, TCGOutOpBinary, outop_shr)                    \
    X(INDEX_op_st, TCGOutOpStore, outop_st)                       \
    X(INDEX_op_st8, TCGOutOpStore, outop_st8)                     \
    X(INDEX_op_st16, TCGOutOpStore, outop_st16)                   \
    X(INDEX_op_sub, TCGOutOpSubtract, outop_sub)                  \
    X(INDEX_op_subbi, TCGOutOpAddSubCarry, outop_subbi)           \
    X(INDEX_op_subbio, TCGOutOpAddSubCarry, outop_subbio)         \
    X(INDEX_op_subbo, TCGOutOpAddSubCarry, outop_subbo)           \
    /* subb1o is implemented with set_borrow + subbio */          \
    X(INDEX_op_subb1o, TCGOutOpAddSubCarry, outop_subbio)         \
    X(INDEX_op_xor, TCGOutOpBinary, outop_xor)                    \
    \
    X(INDEX_op_bswap64, TCGOutOpUnary, outop_bswap64)             \
    X(INDEX_op_extrh_i64_i32, TCGOutOpUnary, outop_extrh_i64_i32) \
    X(INDEX_op_ld32u, TCGOutOpLoad, outop_ld32u)                  \
    X(INDEX_op_ld32s, TCGOutOpLoad, outop_ld32s)                  \
    X(INDEX_op_st32, TCGOutOpStore, outop_st)
