/*
 *  MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4/PNI support
 *
 *  Copyright (c) 2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#if SHIFT == 0
#define Reg MMXReg
#define SUFFIX _mmx
#else
#define Reg ZMMReg
#if SHIFT == 1
#define SUFFIX _xmm
#else
#define SUFFIX _ymm
#endif
#endif

#define dh_alias_Reg ptr
#define dh_alias_ZMMReg ptr
#define dh_alias_MMXReg ptr
#define dh_ctype_Reg Reg *
#define dh_ctype_ZMMReg ZMMReg *
#define dh_ctype_MMXReg MMXReg *
#define dh_typecode_Reg dh_typecode_ptr
#define dh_typecode_ZMMReg dh_typecode_ptr
#define dh_typecode_MMXReg dh_typecode_ptr

DEF_HELPER_4(glue(psrlw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(psraw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(psllw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(psrld, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(psrad, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(pslld, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(psrlq, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(psllq, SUFFIX), void, env, Reg, Reg, Reg)

#if SHIFT >= 1
DEF_HELPER_4(glue(psrldq, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(pslldq, SUFFIX), void, env, Reg, Reg, Reg)
#endif

#define SSE_HELPER_B(name, F)\
    DEF_HELPER_4(glue(name, SUFFIX), void, env, Reg, Reg, Reg)

#define SSE_HELPER_W(name, F)\
    DEF_HELPER_4(glue(name, SUFFIX), void, env, Reg, Reg, Reg)

#define SSE_HELPER_L(name, F)\
    DEF_HELPER_4(glue(name, SUFFIX), void, env, Reg, Reg, Reg)

#define SSE_HELPER_Q(name, F)\
    DEF_HELPER_4(glue(name, SUFFIX), void, env, Reg, Reg, Reg)

#if SHIFT == 0
DEF_HELPER_3(glue(pmulhrw, SUFFIX), void, env, Reg, Reg)
#endif
SSE_HELPER_W(pmulhuw, FMULHUW)
SSE_HELPER_W(pmulhw, FMULHW)

SSE_HELPER_B(pavgb, FAVG)
SSE_HELPER_W(pavgw, FAVG)

DEF_HELPER_4(glue(pmuludq, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(pmaddwd, SUFFIX), void, env, Reg, Reg, Reg)

DEF_HELPER_4(glue(psadbw, SUFFIX), void, env, Reg, Reg, Reg)
#if SHIFT < 2
DEF_HELPER_4(glue(maskmov, SUFFIX), void, env, Reg, Reg, tl)
#endif

#if SHIFT == 0
DEF_HELPER_3(glue(pshufw, SUFFIX), void, Reg, Reg, int)
#else
DEF_HELPER_3(glue(pshufd, SUFFIX), void, Reg, Reg, int)
DEF_HELPER_3(glue(pshuflw, SUFFIX), void, Reg, Reg, int)
DEF_HELPER_3(glue(pshufhw, SUFFIX), void, Reg, Reg, int)
#endif

#if SHIFT >= 1
/*
 * The SSE floating-point helpers from here on (not 3DNow!'s), with
 * SHUFPS/PD, BLENDPS/PD, BLENDVPS/PD, MOVMSKPS/PD and VPERMILPS/PD, read
 * and write only their arguments and env->sse_status, and never raise an
 * exception, so they are TCG_CALL_NO_RWG: TCG need not sync the guest's
 * registers around them. COMISS, UCOMISS, COMISD, UCOMISD, VTESTPS and
 * VTESTPD write CC_SRC and CC_OP, which TCG holds as globals, so they
 * keep the default flags.
 */

/* FPU ops */
/* XXX: not accurate */

#define SSE_HELPER_P4(name)                                             \
    DEF_HELPER_FLAGS_4(glue(name ## ps, SUFFIX), TCG_CALL_NO_RWG,       \
                       void, env, Reg, Reg, Reg)                        \
    DEF_HELPER_FLAGS_4(glue(name ## pd, SUFFIX), TCG_CALL_NO_RWG,       \
                       void, env, Reg, Reg, Reg)

#define SSE_HELPER_P3(name, ...)                                        \
    DEF_HELPER_FLAGS_3(glue(name ## ps, SUFFIX), TCG_CALL_NO_RWG,       \
                       void, env, Reg, Reg)                             \
    DEF_HELPER_FLAGS_3(glue(name ## pd, SUFFIX), TCG_CALL_NO_RWG,       \
                       void, env, Reg, Reg)

#if SHIFT == 1
#define SSE_HELPER_S4(name)                                             \
    SSE_HELPER_P4(name)                                                 \
    DEF_HELPER_FLAGS_4(name ## ss, TCG_CALL_NO_RWG,                     \
                       void, env, Reg, Reg, Reg)                        \
    DEF_HELPER_FLAGS_4(name ## sd, TCG_CALL_NO_RWG,                     \
                       void, env, Reg, Reg, Reg)
#define SSE_HELPER_S3(name)                                             \
    SSE_HELPER_P3(name)                                                 \
    DEF_HELPER_FLAGS_4(name ## ss, TCG_CALL_NO_RWG,                     \
                       void, env, Reg, Reg, Reg)                        \
    DEF_HELPER_FLAGS_4(name ## sd, TCG_CALL_NO_RWG,                     \
                       void, env, Reg, Reg, Reg)
#else
#define SSE_HELPER_S4(name, ...) SSE_HELPER_P4(name)
#define SSE_HELPER_S3(name, ...) SSE_HELPER_P3(name)
#endif

DEF_HELPER_FLAGS_4(glue(shufps, SUFFIX), TCG_CALL_NO_RWG,
                   void, Reg, Reg, Reg, int)
DEF_HELPER_FLAGS_4(glue(shufpd, SUFFIX), TCG_CALL_NO_RWG,
                   void, Reg, Reg, Reg, int)

SSE_HELPER_S4(add)
SSE_HELPER_S4(sub)
SSE_HELPER_S4(mul)
SSE_HELPER_S4(div)
SSE_HELPER_S4(min)
SSE_HELPER_S4(max)

SSE_HELPER_S3(sqrt)

DEF_HELPER_FLAGS_3(glue(cvtps2pd, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg)
DEF_HELPER_FLAGS_3(glue(cvtpd2ps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg)
DEF_HELPER_FLAGS_3(glue(cvtdq2ps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg)
DEF_HELPER_FLAGS_3(glue(cvtdq2pd, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg)

DEF_HELPER_FLAGS_3(glue(cvtps2dq, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, ZMMReg, ZMMReg)
DEF_HELPER_FLAGS_3(glue(cvtpd2dq, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, ZMMReg, ZMMReg)

DEF_HELPER_FLAGS_3(glue(cvttps2dq, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, ZMMReg, ZMMReg)
DEF_HELPER_FLAGS_3(glue(cvttpd2dq, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, ZMMReg, ZMMReg)

#if SHIFT == 1
DEF_HELPER_FLAGS_4(cvtss2sd, TCG_CALL_NO_RWG, void, env, Reg, Reg, Reg)
DEF_HELPER_FLAGS_4(cvtsd2ss, TCG_CALL_NO_RWG, void, env, Reg, Reg, Reg)
DEF_HELPER_FLAGS_3(cvtpi2ps, TCG_CALL_NO_RWG, void, env, ZMMReg, MMXReg)
DEF_HELPER_FLAGS_3(cvtpi2pd, TCG_CALL_NO_RWG, void, env, ZMMReg, MMXReg)
DEF_HELPER_FLAGS_3(cvtsi2ss, TCG_CALL_NO_RWG, void, env, ZMMReg, i32)
DEF_HELPER_FLAGS_3(cvtsi2sd, TCG_CALL_NO_RWG, void, env, ZMMReg, i32)

#ifdef TARGET_X86_64
DEF_HELPER_FLAGS_3(cvtsq2ss, TCG_CALL_NO_RWG, void, env, ZMMReg, i64)
DEF_HELPER_FLAGS_3(cvtsq2sd, TCG_CALL_NO_RWG, void, env, ZMMReg, i64)
#endif

DEF_HELPER_FLAGS_3(cvtps2pi, TCG_CALL_NO_RWG, void, env, MMXReg, ZMMReg)
DEF_HELPER_FLAGS_3(cvtpd2pi, TCG_CALL_NO_RWG, void, env, MMXReg, ZMMReg)
DEF_HELPER_FLAGS_2(cvtss2si, TCG_CALL_NO_RWG, s32, env, ZMMReg)
DEF_HELPER_FLAGS_2(cvtsd2si, TCG_CALL_NO_RWG, s32, env, ZMMReg)
#ifdef TARGET_X86_64
DEF_HELPER_FLAGS_2(cvtss2sq, TCG_CALL_NO_RWG, s64, env, ZMMReg)
DEF_HELPER_FLAGS_2(cvtsd2sq, TCG_CALL_NO_RWG, s64, env, ZMMReg)
#endif

DEF_HELPER_FLAGS_3(cvttps2pi, TCG_CALL_NO_RWG, void, env, MMXReg, ZMMReg)
DEF_HELPER_FLAGS_3(cvttpd2pi, TCG_CALL_NO_RWG, void, env, MMXReg, ZMMReg)
DEF_HELPER_FLAGS_2(cvttss2si, TCG_CALL_NO_RWG, s32, env, ZMMReg)
DEF_HELPER_FLAGS_2(cvttsd2si, TCG_CALL_NO_RWG, s32, env, ZMMReg)
#ifdef TARGET_X86_64
DEF_HELPER_FLAGS_2(cvttss2sq, TCG_CALL_NO_RWG, s64, env, ZMMReg)
DEF_HELPER_FLAGS_2(cvttsd2sq, TCG_CALL_NO_RWG, s64, env, ZMMReg)
#endif
#endif

DEF_HELPER_FLAGS_3(glue(rsqrtps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, ZMMReg, ZMMReg)
DEF_HELPER_FLAGS_3(glue(rcpps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, ZMMReg, ZMMReg)

#if SHIFT == 1
DEF_HELPER_FLAGS_4(rsqrtss, TCG_CALL_NO_RWG, void, env, ZMMReg, ZMMReg, ZMMReg)
DEF_HELPER_FLAGS_4(rcpss, TCG_CALL_NO_RWG, void, env, ZMMReg, ZMMReg, ZMMReg)
DEF_HELPER_3(extrq_r, void, env, ZMMReg, ZMMReg)
DEF_HELPER_4(extrq_i, void, env, ZMMReg, int, int)
DEF_HELPER_3(insertq_r, void, env, ZMMReg, ZMMReg)
DEF_HELPER_5(insertq_i, void, env, ZMMReg, ZMMReg, int, int)
#endif

SSE_HELPER_P4(hadd)
SSE_HELPER_P4(hsub)
SSE_HELPER_P4(addsub)

#define SSE_HELPER_CMP(name, F, C) SSE_HELPER_S4(name)

SSE_HELPER_CMP(cmpeq, FPU_CMPQ, FPU_EQ)
SSE_HELPER_CMP(cmplt, FPU_CMPS, FPU_LT)
SSE_HELPER_CMP(cmple, FPU_CMPS, FPU_LE)
SSE_HELPER_CMP(cmpunord, FPU_CMPQ,  FPU_UNORD)
SSE_HELPER_CMP(cmpneq, FPU_CMPQ, !FPU_EQ)
SSE_HELPER_CMP(cmpnlt, FPU_CMPS, !FPU_LT)
SSE_HELPER_CMP(cmpnle, FPU_CMPS, !FPU_LE)
SSE_HELPER_CMP(cmpord, FPU_CMPQ, !FPU_UNORD)

SSE_HELPER_CMP(cmpequ, FPU_CMPQ, FPU_EQU)
SSE_HELPER_CMP(cmpnge, FPU_CMPS, !FPU_GE)
SSE_HELPER_CMP(cmpngt, FPU_CMPS, !FPU_GT)
SSE_HELPER_CMP(cmpfalse, FPU_CMPQ,  FPU_FALSE)
SSE_HELPER_CMP(cmpnequ, FPU_CMPQ, !FPU_EQU)
SSE_HELPER_CMP(cmpge, FPU_CMPS, FPU_GE)
SSE_HELPER_CMP(cmpgt, FPU_CMPS, FPU_GT)
SSE_HELPER_CMP(cmptrue, FPU_CMPQ,  !FPU_FALSE)

SSE_HELPER_CMP(cmpeqs, FPU_CMPS, FPU_EQ)
SSE_HELPER_CMP(cmpltq, FPU_CMPQ, FPU_LT)
SSE_HELPER_CMP(cmpleq, FPU_CMPQ, FPU_LE)
SSE_HELPER_CMP(cmpunords, FPU_CMPS,  FPU_UNORD)
SSE_HELPER_CMP(cmpneqq, FPU_CMPS, !FPU_EQ)
SSE_HELPER_CMP(cmpnltq, FPU_CMPQ, !FPU_LT)
SSE_HELPER_CMP(cmpnleq, FPU_CMPQ, !FPU_LE)
SSE_HELPER_CMP(cmpords, FPU_CMPS, !FPU_UNORD)

SSE_HELPER_CMP(cmpequs, FPU_CMPS, FPU_EQU)
SSE_HELPER_CMP(cmpngeq, FPU_CMPQ, !FPU_GE)
SSE_HELPER_CMP(cmpngtq, FPU_CMPQ, !FPU_GT)
SSE_HELPER_CMP(cmpfalses, FPU_CMPS,  FPU_FALSE)
SSE_HELPER_CMP(cmpnequs, FPU_CMPS, !FPU_EQU)
SSE_HELPER_CMP(cmpgeq, FPU_CMPQ, FPU_GE)
SSE_HELPER_CMP(cmpgtq, FPU_CMPQ, FPU_GT)
SSE_HELPER_CMP(cmptrues, FPU_CMPS,  !FPU_FALSE)

#if SHIFT == 1
DEF_HELPER_3(ucomiss, void, env, Reg, Reg)
DEF_HELPER_3(comiss, void, env, Reg, Reg)
DEF_HELPER_3(ucomisd, void, env, Reg, Reg)
DEF_HELPER_3(comisd, void, env, Reg, Reg)
#endif

DEF_HELPER_FLAGS_2(glue(movmskps, SUFFIX), TCG_CALL_NO_RWG, i32, env, Reg)
DEF_HELPER_FLAGS_2(glue(movmskpd, SUFFIX), TCG_CALL_NO_RWG, i32, env, Reg)
#endif

DEF_HELPER_4(glue(packsswb, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(packuswb, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(packssdw, SUFFIX), void, env, Reg, Reg, Reg)
#define UNPCK_OP(name, base)                                       \
    DEF_HELPER_4(glue(punpck ## name ## bw, SUFFIX), void, env, Reg, Reg, Reg) \
    DEF_HELPER_4(glue(punpck ## name ## wd, SUFFIX), void, env, Reg, Reg, Reg) \
    DEF_HELPER_4(glue(punpck ## name ## dq, SUFFIX), void, env, Reg, Reg, Reg)

UNPCK_OP(l, 0)
UNPCK_OP(h, 1)

#if SHIFT >= 1
DEF_HELPER_4(glue(punpcklqdq, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(punpckhqdq, SUFFIX), void, env, Reg, Reg, Reg)
#endif

/* 3DNow! float ops */
#if SHIFT == 0
DEF_HELPER_3(pi2fd, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pi2fw, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pf2id, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pf2iw, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfacc, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfadd, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfcmpeq, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfcmpge, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfcmpgt, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfmax, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfmin, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfmul, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfnacc, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfpnacc, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfrcp, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfrsqrt, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfsub, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pfsubr, void, env, MMXReg, MMXReg)
DEF_HELPER_3(pswapd, void, env, MMXReg, MMXReg)
#endif

/* SSSE3 op helpers */
DEF_HELPER_4(glue(phaddw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(phaddd, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(phaddsw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(phsubw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(phsubd, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(phsubsw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(pmaddubsw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(pmulhrsw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(pshufb, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(psignb, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(psignw, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(psignd, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_5(glue(palignr, SUFFIX), void, env, Reg, Reg, Reg, i32)

/* SSE4.1 op helpers */
#if SHIFT >= 1
DEF_HELPER_5(glue(pblendvb, SUFFIX), void, env, Reg, Reg, Reg, Reg)
DEF_HELPER_FLAGS_5(glue(blendvps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg, Reg)
DEF_HELPER_FLAGS_5(glue(blendvpd, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg, Reg)
DEF_HELPER_3(glue(ptest, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovsxbw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovsxbd, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovsxbq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovsxwd, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovsxwq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovsxdq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovzxbw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovzxbd, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovzxbq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovzxwd, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovzxwq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovzxdq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovsldup, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovshdup, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmovdldup, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_4(glue(pmuldq, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(packusdw, SUFFIX), void, env, Reg, Reg, Reg)
#if SHIFT == 1
DEF_HELPER_3(glue(phminposuw, SUFFIX), void, env, Reg, Reg)
#endif
DEF_HELPER_FLAGS_4(glue(roundps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, i32)
DEF_HELPER_FLAGS_4(glue(roundpd, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, i32)
#if SHIFT == 1
DEF_HELPER_FLAGS_5(roundss_xmm, TCG_CALL_NO_RWG, void, env, Reg, Reg, Reg, i32)
DEF_HELPER_FLAGS_5(roundsd_xmm, TCG_CALL_NO_RWG, void, env, Reg, Reg, Reg, i32)
#endif
DEF_HELPER_FLAGS_5(glue(blendps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg, i32)
DEF_HELPER_FLAGS_5(glue(blendpd, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg, i32)
DEF_HELPER_5(glue(pblendw, SUFFIX), void, env, Reg, Reg, Reg, i32)
DEF_HELPER_FLAGS_5(glue(dpps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg, i32)
#if SHIFT == 1
DEF_HELPER_FLAGS_5(glue(dppd, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg, i32)
#endif
DEF_HELPER_5(glue(mpsadbw, SUFFIX), void, env, Reg, Reg, Reg, i32)
#endif

/* SSE4.2 op helpers */
#if SHIFT == 1
DEF_HELPER_4(glue(pcmpestri, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pcmpestrm, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pcmpistri, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pcmpistrm, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_3(crc32, tl, i32, tl, i32)
#endif

/* AES-NI op helpers */
#if SHIFT >= 1
DEF_HELPER_4(glue(aesdec, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(aesdeclast, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(aesenc, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(aesenclast, SUFFIX), void, env, Reg, Reg, Reg)
#if SHIFT == 1
DEF_HELPER_3(glue(aesimc, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_4(glue(aeskeygenassist, SUFFIX), void, env, Reg, Reg, i32)
#endif
DEF_HELPER_5(glue(pclmulqdq, SUFFIX), void, env, Reg, Reg, Reg, i32)
#endif

/* F16C helpers */
#if SHIFT >= 1
DEF_HELPER_FLAGS_3(glue(cvtph2ps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg)
DEF_HELPER_FLAGS_4(glue(cvtps2ph, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, int)
#endif

/* FMA3 helpers */
#if SHIFT == 1
DEF_HELPER_FLAGS_6(fma4ss, TCG_CALL_NO_RWG, void, env, Reg, Reg, Reg, Reg, int)
DEF_HELPER_FLAGS_6(fma4sd, TCG_CALL_NO_RWG, void, env, Reg, Reg, Reg, Reg, int)
#endif

#if SHIFT >= 1
DEF_HELPER_FLAGS_7(glue(fma4ps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg, Reg, int, int)
DEF_HELPER_FLAGS_7(glue(fma4pd, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg, Reg, int, int)
#endif

/* AVX helpers */
#if SHIFT >= 1
DEF_HELPER_FLAGS_4(glue(vpermilpd, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg)
DEF_HELPER_FLAGS_4(glue(vpermilps, SUFFIX), TCG_CALL_NO_RWG,
                   void, env, Reg, Reg, Reg)
DEF_HELPER_FLAGS_3(glue(vpermilpd_imm, SUFFIX), TCG_CALL_NO_RWG,
                   void, Reg, Reg, i32)
DEF_HELPER_FLAGS_3(glue(vpermilps_imm, SUFFIX), TCG_CALL_NO_RWG,
                   void, Reg, Reg, i32)
DEF_HELPER_4(glue(vpsrlvd, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(vpsravd, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(vpsllvd, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(vpsrlvq, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(vpsravq, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(vpsllvq, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_3(glue(vtestps, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(vtestpd, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_4(glue(vpmaskmovd_st, SUFFIX), void, env, Reg, Reg, tl)
DEF_HELPER_4(glue(vpmaskmovq_st, SUFFIX), void, env, Reg, Reg, tl)
DEF_HELPER_4(glue(vpmaskmovd, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_4(glue(vpmaskmovq, SUFFIX), void, env, Reg, Reg, Reg)
DEF_HELPER_7(glue(vpgatherdd, SUFFIX), void, env, Reg, Reg, Reg, tl, i32, tl)
DEF_HELPER_7(glue(vpgatherdq, SUFFIX), void, env, Reg, Reg, Reg, tl, i32, tl)
DEF_HELPER_7(glue(vpgatherqd, SUFFIX), void, env, Reg, Reg, Reg, tl, i32, tl)
DEF_HELPER_7(glue(vpgatherqq, SUFFIX), void, env, Reg, Reg, Reg, tl, i32, tl)
#if SHIFT == 2
DEF_HELPER_3(vpermd_ymm, void, Reg, Reg, Reg)
DEF_HELPER_4(vpermdq_ymm, void, Reg, Reg, Reg, i32)
DEF_HELPER_3(vpermq_ymm, void, Reg, Reg, i32)
#endif
#endif

/* SHA helpers */
#if SHIFT == 1
DEF_HELPER_3(sha1rnds4_f0, void, Reg, Reg, Reg)
DEF_HELPER_3(sha1rnds4_f1, void, Reg, Reg, Reg)
DEF_HELPER_3(sha1rnds4_f2, void, Reg, Reg, Reg)
DEF_HELPER_3(sha1rnds4_f3, void, Reg, Reg, Reg)
DEF_HELPER_3(sha1nexte, void, Reg, Reg, Reg)
DEF_HELPER_3(sha1msg1, void, Reg, Reg, Reg)
DEF_HELPER_3(sha1msg2, void, Reg, Reg, Reg)
DEF_HELPER_5(sha256rnds2, void, Reg, Reg, Reg, i32, i32)
DEF_HELPER_3(sha256msg1, void, Reg, Reg, Reg)
DEF_HELPER_3(sha256msg2, void, Reg, Reg, Reg)
#endif

#undef SHIFT
#undef Reg
#undef SUFFIX

#undef SSE_HELPER_B
#undef SSE_HELPER_W
#undef SSE_HELPER_L
#undef SSE_HELPER_Q
#undef SSE_HELPER_S3
#undef SSE_HELPER_S4
#undef SSE_HELPER_P3
#undef SSE_HELPER_P4
#undef SSE_HELPER_CMP
#undef UNPCK_OP
