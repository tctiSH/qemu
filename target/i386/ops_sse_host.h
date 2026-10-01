/*
 * x86 SSE/AVX floating point on the host's NEON unit (AArch64 hosts)
 *
 * The SSE float helpers normally run every lane through softfloat. For the
 * common case, AArch64 computes bit-identical results, so these fast paths do
 * a whole vector in a few instructions, and return false (softfloat then does
 * the work) whenever the two architectures could differ:
 *
 *  - MXCSR rounding other than round-to-nearest, or DAZ/FTZ set: the host
 *    runs with FPCR at its defaults (nearest, no flush), as hardfloat assumes.
 *  - A NaN result: the choice of NaN (operand order, SNaN vs QNaN priority)
 *    and the default NaN's sign differ. Every NaN input to add, sub, mul, div
 *    or FMA gives a NaN result, so this covers NaN inputs too, and every
 *    invalid operation.
 *
 * The exception flags are sticky, and in practice MXCSR.PE is set as soon as
 * a program has done any inexact arithmetic. With PE set nobody can tell
 * whether this operation was inexact, so there is nothing to compute; the
 * rarer flags need attention only while they are still clear:
 *
 *  - DE (a denormal input) has no AArch64 equivalent: bail on denormal
 *    inputs unless DE is already set. The result does not depend on it.
 *  - OE and ZE: an infinite result from finite inputs is an overflow, or for
 *    a divide possibly a division by zero; bail unless both are set.
 *  - UE: only a multiply, divide or FMA can underflow (a tiny sum of two
 *    non-NaN floats is exact, and softfloat raises underflow only when
 *    inexact). Bail on a tiny result from nonzero factors unless UE is set.
 *    Nearest-even rounding gives the same result either way.
 *
 * While PE is clear the paths below clear FPSR, compute, and read it back:
 * its cumulative flags map one to one onto softfloat's (IOC invalid, DZC
 * divbyzero, OFC overflow, IXC inexact), except that AArch64 detects
 * tininess before rounding and x86 after, so UFC bails. Writing FPSR costs
 * over ten nanoseconds on Apple cores, hence the sticky-flag path above.
 *
 * min, max and the compares raise no flags once NaN inputs (and denormal
 * ones, while DE is clear) are excluded, and are exact selects.
 *
 * Results are computed into temporaries and stored only on success: the
 * destination may alias a source, and a fallback must see the inputs.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef TARGET_I386_OPS_SSE_HOST_H
#define TARGET_I386_OPS_SSE_HOST_H

enum { SSE_HOST_ADD, SSE_HOST_SUB, SSE_HOST_MUL, SSE_HOST_DIV };
enum { SSE_HOST_PACKSSWB, SSE_HOST_PACKUSWB, SSE_HOST_PACKSSDW,
       SSE_HOST_PACKUSDW };

#if defined(__aarch64__) && !HOST_BIG_ENDIAN
#include <arm_neon.h>

#define FPSR_IOC (1 << 0)
#define FPSR_DZC (1 << 1)
#define FPSR_OFC (1 << 2)
#define FPSR_UFC (1 << 3)
#define FPSR_IXC (1 << 4)
#define FPSR_IDC (1 << 7)

static inline bool sse_host_mode_ok(CPUX86State *env)
{
    float_status *s = &env->sse_status;

    return s->float_rounding_mode == float_round_nearest_even &&
           !s->flush_to_zero && !s->flush_inputs_to_zero;
}

static inline int sse_host_flags(CPUX86State *env)
{
    return get_float_exception_flags(&env->sse_status);
}

/*
 * Clear FPSR before the computation and read it after. The asm operands
 * pin the order: inputs are "modified" by the clear, results are consumed
 * by the read, so the compiler cannot move the arithmetic across either.
 */
#define SSE_HOST_CLEAR(...) \
    asm volatile("msr fpsr, xzr" : __VA_ARGS__ :: "memory")
#define SSE_HOST_READ(f, ...) \
    asm volatile("mrs %0, fpsr" : "=r"(f) : __VA_ARGS__ : "memory")

/* True (and the flags raised) when the host result is x86's. */
static inline bool sse_host_finish(CPUX86State *env, uint64_t fpsr, bool bad)
{
    int flags = 0;

    if (bad || (fpsr & (FPSR_UFC | FPSR_IDC))) {
        return false;
    }
    if (fpsr & FPSR_IOC) {
        flags |= float_flag_invalid;
    }
    if (fpsr & FPSR_DZC) {
        flags |= float_flag_divbyzero;
    }
    if (fpsr & FPSR_OFC) {
        flags |= float_flag_overflow;
    }
    if (fpsr & FPSR_IXC) {
        flags |= float_flag_inexact;
    }
    float_raise(flags, &env->sse_status);
    return true;
}

/*
 * Lane classification, all-ones where true. On the magnitude m (sign
 * cleared): denormal is 0 < m < min normal, tiny is m <= min normal (zero
 * included), finite is m < infinity, nonzero is m != 0.
 */
static inline uint32x4_t sse_host_mag_s(float32x4_t x)
{
    return vandq_u32(vreinterpretq_u32_f32(x), vdupq_n_u32(0x7fffffff));
}

static inline uint64x2_t sse_host_mag_d(float64x2_t x)
{
    return vandq_u64(vreinterpretq_u64_f64(x),
                     vdupq_n_u64(0x7fffffffffffffffull));
}

static inline uint32x4_t sse_host_denormal_s(float32x4_t x)
{
    return vcltq_u32(vsubq_u32(sse_host_mag_s(x), vdupq_n_u32(1)),
                     vdupq_n_u32(0x007fffff));
}

static inline uint32x4_t sse_host_denormal_d(float64x2_t x)
{
    return vreinterpretq_u32_u64(
        vcltq_u64(vsubq_u64(sse_host_mag_d(x), vdupq_n_u64(1)),
                  vdupq_n_u64(0x000fffffffffffffull)));
}

static inline uint32x4_t sse_host_tiny_s(float32x4_t x)
{
    return vcleq_u32(sse_host_mag_s(x), vdupq_n_u32(0x00800000));
}

static inline uint32x4_t sse_host_tiny_d(float64x2_t x)
{
    return vreinterpretq_u32_u64(
        vcleq_u64(sse_host_mag_d(x), vdupq_n_u64(0x0010000000000000ull)));
}

static inline uint32x4_t sse_host_finite_s(float32x4_t x)
{
    return vcltq_u32(sse_host_mag_s(x), vdupq_n_u32(0x7f800000));
}

static inline uint32x4_t sse_host_finite_d(float64x2_t x)
{
    return vreinterpretq_u32_u64(
        vcltq_u64(sse_host_mag_d(x), vdupq_n_u64(0x7ff0000000000000ull)));
}

static inline uint32x4_t sse_host_nonzero_s(float32x4_t x)
{
    return vtstq_u32(vreinterpretq_u32_f32(x), vdupq_n_u32(0x7fffffff));
}

static inline uint32x4_t sse_host_nonzero_d(float64x2_t x)
{
    return vreinterpretq_u32_u64(
        vtstq_u64(vreinterpretq_u64_f64(x),
                  vdupq_n_u64(0x7fffffffffffffffull)));
}

static inline uint32x4_t sse_host_nan_s(float32x4_t x)
{
    return vmvnq_u32(vceqq_f32(x, x));
}

static inline uint32x4_t sse_host_nan_d(float64x2_t x)
{
    return vmvnq_u32(vreinterpretq_u32_u64(vceqq_f64(x, x)));
}

static inline bool sse_host_any(uint32x4_t m)
{
    return vmaxvq_u32(m) != 0;
}

/*
 * The lanes of a result r = a op b (or of an FMA, with c) that the sticky
 * flags in `flags` cannot vouch for; see the comment at the top.
 */
#define SSE_HOST_CHECK(w, flags, op, r, a, b, c, fma)                       \
    ({                                                                      \
        uint32x4_t bad_ = sse_host_nan_##w(r);                              \
        if (!((flags) & float_flag_input_denormal_used)) {                  \
            bad_ = vorrq_u32(bad_, vorrq_u32(sse_host_denormal_##w(a),      \
                                             sse_host_denormal_##w(b)));    \
            if (fma) {                                                      \
                bad_ = vorrq_u32(bad_, sse_host_denormal_##w(c));           \
            }                                                               \
        }                                                                   \
        if (!((flags) & float_flag_overflow) ||                             \
            ((op) == SSE_HOST_DIV && !((flags) & float_flag_divbyzero))) {  \
            uint32x4_t fin_ = vandq_u32(sse_host_finite_##w(a),             \
                                        sse_host_finite_##w(b));            \
            if (fma) {                                                      \
                fin_ = vandq_u32(fin_, sse_host_finite_##w(c));             \
            }                                                               \
            bad_ = vorrq_u32(bad_, vbicq_u32(fin_, sse_host_finite_##w(r))); \
        }                                                                   \
        if (!((flags) & float_flag_underflow) &&                            \
            ((op) == SSE_HOST_MUL || (op) == SSE_HOST_DIV || (fma))) {      \
            uint32x4_t nz_ = sse_host_nonzero_##w(a);                       \
            if ((op) != SSE_HOST_DIV) {                                     \
                nz_ = vandq_u32(nz_, sse_host_nonzero_##w(b));              \
            }                                                               \
            bad_ = vorrq_u32(bad_, vandq_u32(nz_, sse_host_tiny_##w(r)));   \
        }                                                                   \
        bad_;                                                               \
    })

static inline float32x4_t sse_host_op_s(float32x4_t a, float32x4_t b, int op)
{
    switch (op) {
    case SSE_HOST_ADD:
        return vaddq_f32(a, b);
    case SSE_HOST_SUB:
        return vsubq_f32(a, b);
    case SSE_HOST_MUL:
        return vmulq_f32(a, b);
    default:
        return vdivq_f32(a, b);
    }
}

static inline float64x2_t sse_host_op_d(float64x2_t a, float64x2_t b, int op)
{
    switch (op) {
    case SSE_HOST_ADD:
        return vaddq_f64(a, b);
    case SSE_HOST_SUB:
        return vsubq_f64(a, b);
    case SSE_HOST_MUL:
        return vmulq_f64(a, b);
    default:
        return vdivq_f64(a, b);
    }
}

/*
 * Packed float32 (4 or 8 lanes) and float64 (2 or 4 lanes): d = a op b.
 * One template, instantiated for both widths.
 */
#define SSE_HOST_PACKED(w, T, VT, LD, ST, PER)                              \
static inline bool sse_host_p##w(CPUX86State *env, void *d, const void *a,  \
                                 const void *b, int lanes, int op)          \
{                                                                           \
    int flags = sse_host_flags(env);                                        \
    int n = lanes / PER;                                                    \
    uint32x4_t bad = vdupq_n_u32(0);                                        \
    VT r[2];                                                                \
    uint64_t fpsr;                                                          \
                                                                            \
    if (!sse_host_mode_ok(env)) {                                           \
        return false;                                                       \
    }                                                                       \
    if (!(flags & float_flag_inexact)) {                                    \
        SSE_HOST_CLEAR();                                                   \
    }                                                                       \
    for (int i = 0; i < n; i++) {                                           \
        VT x = LD((const T *)a + PER * i), y = LD((const T *)b + PER * i);  \
        r[i] = sse_host_op_##w(x, y, op);                                   \
        bad = vorrq_u32(bad, SSE_HOST_CHECK(w, flags, op, r[i], x, y,       \
                                            x, false));                     \
    }                                                                       \
    if (n == 1) {                                                           \
        r[1] = r[0];                                                        \
    }                                                                       \
    if (!(flags & float_flag_inexact)) {                                    \
        SSE_HOST_READ(fpsr, "w"(r[0]), "w"(r[1]));                          \
        if (!sse_host_finish(env, fpsr, sse_host_any(bad))) {               \
            return false;                                                   \
        }                                                                   \
    } else if (sse_host_any(bad)) {                                         \
        return false;                                                       \
    }                                                                       \
    for (int i = 0; i < n; i++) {                                           \
        ST((T *)d + PER * i, r[i]);                                         \
    }                                                                       \
    return true;                                                            \
}

SSE_HOST_PACKED(s, float, float32x4_t, vld1q_f32, vst1q_f32, 4)
SSE_HOST_PACKED(d, double, float64x2_t, vld1q_f64, vst1q_f64, 2)

/*
 * Scalar float32 and float64 (the ss and sd forms): *d = a op b, lane 0
 * only. The same checks, on a vector holding the one value in every lane.
 */
static inline bool sse_host_ss(CPUX86State *env, float32 *d, float32 a,
                               float32 b, int op)
{
    int flags = sse_host_flags(env);
    float32x4_t x = vreinterpretq_f32_u32(vdupq_n_u32(a));
    float32x4_t y = vreinterpretq_f32_u32(vdupq_n_u32(b));
    float32x4_t r;
    uint64_t fpsr;
    bool bad;

    if (!sse_host_mode_ok(env)) {
        return false;
    }
    if (!(flags & float_flag_inexact)) {
        SSE_HOST_CLEAR("+w"(x), "+w"(y));
    }
    r = sse_host_op_s(x, y, op);
    bad = sse_host_any(SSE_HOST_CHECK(s, flags, op, r, x, y, x, false));
    if (!(flags & float_flag_inexact)) {
        SSE_HOST_READ(fpsr, "w"(r));
        if (!sse_host_finish(env, fpsr, bad)) {
            return false;
        }
    } else if (bad) {
        return false;
    }
    *d = vgetq_lane_u32(vreinterpretq_u32_f32(r), 0);
    return true;
}

static inline bool sse_host_sd(CPUX86State *env, float64 *d, float64 a,
                               float64 b, int op)
{
    int flags = sse_host_flags(env);
    float64x2_t x = vreinterpretq_f64_u64(vdupq_n_u64(a));
    float64x2_t y = vreinterpretq_f64_u64(vdupq_n_u64(b));
    float64x2_t r;
    uint64_t fpsr;
    bool bad;

    if (!sse_host_mode_ok(env)) {
        return false;
    }
    if (!(flags & float_flag_inexact)) {
        SSE_HOST_CLEAR("+w"(x), "+w"(y));
    }
    r = sse_host_op_d(x, y, op);
    bad = sse_host_any(SSE_HOST_CHECK(d, flags, op, r, x, y, x, false));
    if (!(flags & float_flag_inexact)) {
        SSE_HOST_READ(fpsr, "w"(r));
        if (!sse_host_finish(env, fpsr, bad)) {
            return false;
        }
    } else if (bad) {
        return false;
    }
    *d = vgetq_lane_u64(vreinterpretq_u64_f64(r), 0);
    return true;
}

/*
 * Fused multiply-add, d = (a * b) + c with softfloat's negate flags, over
 * 4 or 8 float32 (2 or 4 float64) lanes; `flip` toggles the flags on odd
 * lanes (fmaddsub). Negating an operand is exact, so -(a * b) = (-a) * b and
 * the sign of a zero result comes out as softfloat's.
 */
#define SSE_HOST_FMA(w, T, VT, UT, LD, ST, PER, DUP, EOR, FMA, CU, CF, SIGN) \
static inline bool sse_host_fma_p##w(CPUX86State *env, void *d,             \
                                     const void *a, const void *b,          \
                                     const void *c, int lanes,              \
                                     int flags, int flip)                   \
{                                                                           \
    int st = sse_host_flags(env);                                           \
    int n = lanes / PER, f1 = flags ^ flip;                                 \
    uint32x4_t bad = vdupq_n_u32(0);                                        \
    UT np, nc;                                                              \
    VT r[2];                                                                \
    uint64_t fpsr;                                                          \
                                                                            \
    if (!sse_host_mode_ok(env) ||                                           \
        ((flags | f1) & ~(float_muladd_negate_c |                           \
                          float_muladd_negate_product))) {                  \
        return false;                                                       \
    }                                                                       \
    /* even lanes take `flags`, odd lanes `flags ^ flip` */                 \
    np = DUP(flags & float_muladd_negate_product ? SIGN : 0);               \
    nc = DUP(flags & float_muladd_negate_c ? SIGN : 0);                     \
    for (int l = 1; l < PER; l += 2) {                                      \
        np[l] = f1 & float_muladd_negate_product ? SIGN : 0;                \
        nc[l] = f1 & float_muladd_negate_c ? SIGN : 0;                      \
    }                                                                       \
    if (!(st & float_flag_inexact)) {                                       \
        SSE_HOST_CLEAR();                                                   \
    }                                                                       \
    for (int i = 0; i < n; i++) {                                           \
        VT x = LD((const T *)a + PER * i), y = LD((const T *)b + PER * i);  \
        VT z = LD((const T *)c + PER * i);                                  \
        x = CF(EOR(CU(x), np));                                             \
        z = CF(EOR(CU(z), nc));                                             \
        r[i] = FMA(z, x, y);                                                \
        bad = vorrq_u32(bad, SSE_HOST_CHECK(w, st, SSE_HOST_ADD, r[i],      \
                                            x, y, z, true));                \
    }                                                                       \
    if (n == 1) {                                                           \
        r[1] = r[0];                                                        \
    }                                                                       \
    if (!(st & float_flag_inexact)) {                                       \
        SSE_HOST_READ(fpsr, "w"(r[0]), "w"(r[1]));                          \
        if (!sse_host_finish(env, fpsr, sse_host_any(bad))) {               \
            return false;                                                   \
        }                                                                   \
    } else if (sse_host_any(bad)) {                                         \
        return false;                                                       \
    }                                                                       \
    for (int i = 0; i < n; i++) {                                           \
        ST((T *)d + PER * i, r[i]);                                         \
    }                                                                       \
    return true;                                                            \
}

SSE_HOST_FMA(s, float, float32x4_t, uint32x4_t, vld1q_f32, vst1q_f32, 4,
             vdupq_n_u32, veorq_u32, vfmaq_f32, vreinterpretq_u32_f32,
             vreinterpretq_f32_u32, 0x80000000u)
SSE_HOST_FMA(d, double, float64x2_t, uint64x2_t, vld1q_f64, vst1q_f64, 2,
             vdupq_n_u64, veorq_u64, vfmaq_f64, vreinterpretq_u64_f64,
             vreinterpretq_f64_u64, 0x8000000000000000ull)

/* The scalar FMA forms: lane 0 of the packed path, with no flip. */
static inline bool sse_host_fma_ss(CPUX86State *env, float32 *d, float32 a,
                                   float32 b, float32 c, int flags)
{
    uint32_t va[4] = { a }, vb[4] = { b }, vc[4] = { c }, r[4];

    if (!sse_host_fma_ps(env, r, va, vb, vc, 4, flags, 0)) {
        return false;
    }
    *d = r[0];
    return true;
}

static inline bool sse_host_fma_sd(CPUX86State *env, float64 *d, float64 a,
                                   float64 b, float64 c, int flags)
{
    uint64_t va[2] = { a }, vb[2] = { b }, vc[2] = { c }, r[2];

    if (!sse_host_fma_pd(env, r, va, vb, vc, 2, flags, 0)) {
        return false;
    }
    *d = r[0];
    return true;
}

/*
 * min, max and compares: with no NaN input, and no denormal one while DE
 * is clear (or DAZ set: denormals then compare as zero), the relation is
 * the host's and nothing is raised. Nothing is rounded, so the other
 * MXCSR modes do not matter.
 */
static inline bool sse_host_plain_ps(CPUX86State *env, const void *a,
                                     const void *b, int lanes)
{
    bool den = !(sse_host_flags(env) & float_flag_input_denormal_used) ||
               env->sse_status.flush_inputs_to_zero;
    uint32x4_t bad = vdupq_n_u32(0);

    for (int i = 0; i < lanes; i += 4) {
        float32x4_t x = vld1q_f32((const float *)a + i);
        float32x4_t y = vld1q_f32((const float *)b + i);

        bad = vorrq_u32(bad, vorrq_u32(sse_host_nan_s(x), sse_host_nan_s(y)));
        if (den) {
            bad = vorrq_u32(bad, vorrq_u32(sse_host_denormal_s(x),
                                           sse_host_denormal_s(y)));
        }
    }
    return !sse_host_any(bad);
}

static inline bool sse_host_plain_pd(CPUX86State *env, const void *a,
                                     const void *b, int lanes)
{
    bool den = !(sse_host_flags(env) & float_flag_input_denormal_used) ||
               env->sse_status.flush_inputs_to_zero;
    uint32x4_t bad = vdupq_n_u32(0);

    for (int i = 0; i < lanes; i += 2) {
        float64x2_t x = vld1q_f64((const double *)a + i);
        float64x2_t y = vld1q_f64((const double *)b + i);

        bad = vorrq_u32(bad, vorrq_u32(sse_host_nan_d(x), sse_host_nan_d(y)));
        if (den) {
            bad = vorrq_u32(bad, vorrq_u32(sse_host_denormal_d(x),
                                           sse_host_denormal_d(y)));
        }
    }
    return !sse_host_any(bad);
}

static inline bool sse_host_plain_s(CPUX86State *env, float32 a, float32 b)
{
    uint32_t va[4] = { a, a, a, a }, vb[4] = { b, b, b, b };

    return sse_host_plain_ps(env, va, vb, 4);
}

static inline bool sse_host_plain_d(CPUX86State *env, float64 a, float64 b)
{
    uint64_t va[2] = { a, a }, vb[2] = { b, b };

    return sse_host_plain_pd(env, va, vb, 2);
}

/* The relation of two non-NaN values, as float32_compare() returns it. */
#define SSE_HOST_REL(a, b) \
    ((a) < (b) ? float_relation_less : \
     (a) == (b) ? float_relation_equal : float_relation_greater)

static inline FloatRelation sse_host_rel_s(float32 a, float32 b)
{
    float fa, fb;

    memcpy(&fa, &a, 4);
    memcpy(&fb, &b, 4);
    return SSE_HOST_REL(fa, fb);
}

static inline FloatRelation sse_host_rel_d(float64 a, float64 b)
{
    double fa, fb;

    memcpy(&fa, &a, 8);
    memcpy(&fb, &b, 8);
    return SSE_HOST_REL(fa, fb);
}

/*
 * x86 min and max return the second operand unless the first is strictly
 * less (min) or greater (max): an exact select.
 */
static inline bool sse_host_minmax_ps(CPUX86State *env, void *d,
                                      const void *a, const void *b,
                                      int lanes, bool max)
{
    float32x4_t r[2];

    if (!sse_host_plain_ps(env, a, b, lanes)) {
        return false;
    }
    for (int i = 0; i < lanes / 4; i++) {
        float32x4_t x = vld1q_f32((const float *)a + 4 * i);
        float32x4_t y = vld1q_f32((const float *)b + 4 * i);

        r[i] = vbslq_f32(max ? vcgtq_f32(x, y) : vcltq_f32(x, y), x, y);
    }
    for (int i = 0; i < lanes / 4; i++) {
        vst1q_f32((float *)d + 4 * i, r[i]);
    }
    return true;
}

static inline bool sse_host_minmax_pd(CPUX86State *env, void *d,
                                      const void *a, const void *b,
                                      int lanes, bool max)
{
    float64x2_t r[2];

    if (!sse_host_plain_pd(env, a, b, lanes)) {
        return false;
    }
    for (int i = 0; i < lanes / 2; i++) {
        float64x2_t x = vld1q_f64((const double *)a + 2 * i);
        float64x2_t y = vld1q_f64((const double *)b + 2 * i);

        r[i] = vbslq_f64(max ? vcgtq_f64(x, y) : vcltq_f64(x, y), x, y);
    }
    for (int i = 0; i < lanes / 2; i++) {
        vst1q_f64((double *)d + 2 * i, r[i]);
    }
    return true;
}

static inline bool sse_host_minmax_ss(CPUX86State *env, float32 *d,
                                      float32 a, float32 b, bool max)
{
    FloatRelation r;

    if (!sse_host_plain_s(env, a, b)) {
        return false;
    }
    r = sse_host_rel_s(a, b);
    *d = (max ? r == float_relation_greater : r == float_relation_less) ? a : b;
    return true;
}

static inline bool sse_host_minmax_sd(CPUX86State *env, float64 *d,
                                      float64 a, float64 b, bool max)
{
    FloatRelation r;

    if (!sse_host_plain_d(env, a, b)) {
        return false;
    }
    r = sse_host_rel_d(a, b);
    *d = (max ? r == float_relation_greater : r == float_relation_less) ? a : b;
    return true;
}

/*
 * dpps over one 128-bit lane: the products and sums in x86's order,
 * (p0 + p1) + (p2 + p3), each rounded, as the softfloat helper does.
 * Products the mask leaves out are +0 and not evaluated at all. A product
 * or partial sum can be an exact denormal without underflowing, and then
 * feeds the next addition as a denormal input: softfloat raises DE for it.
 * With PE set, the same sticky-flag reasoning as above covers all seven
 * operations: a NaN anywhere reaches the result; DE matters for the inputs
 * and the intermediate values; OE for any infinity (conservatively, input
 * or not); UE only for the products. Otherwise it goes through FPSR.
 */
static inline bool sse_host_dpps(CPUX86State *env, float32 *d,
                                 const float32 *v, const float32 *s,
                                 uint32_t mask)
{
#ifdef __clang__
#pragma clang fp contract(off)
#endif
    int flags = sse_host_flags(env);
    bool sticky = flags & float_flag_inexact;
    uint32_t in[8];
    float p[4], t2, t3, t4;
    float32x4_t pv, tv, sv, xv, yv;
    uint32x4_t bad;
    uint64_t fpsr = 0;
    uint32_t bits;

    if (!sse_host_mode_ok(env)) {
        return false;
    }
    for (int i = 0; i < 4; i++) {
        bool used = mask & (0x10 << i);

        in[i] = used ? v[i] : 0;
        in[4 + i] = used ? s[i] : 0;
    }
    xv = vreinterpretq_f32_u32(vld1q_u32(in));
    yv = vreinterpretq_f32_u32(vld1q_u32(in + 4));
    if (!sticky) {
        SSE_HOST_CLEAR();
    }
    for (int i = 0; i < 4; i++) {
        float x, y;

        if (mask & (0x10 << i)) {
            memcpy(&x, &v[i], 4);
            memcpy(&y, &s[i], 4);
            p[i] = x * y;
        } else {
            p[i] = 0.0f;
        }
    }
    t2 = p[0] + p[1];
    t3 = p[2] + p[3];
    t4 = t2 + t3;
    if (!sticky) {
        SSE_HOST_READ(fpsr, "w"(t4), "w"(t2), "w"(t3));
    }
    pv = vld1q_f32(p);
    tv = (float32x4_t) { t2, t3, t4, 0.0f };
    sv = (float32x4_t) { t2, t3, 1.0f, 1.0f };

    bad = sse_host_nan_s(tv);
    if (!(flags & float_flag_input_denormal_used) || !sticky) {
        bad = vorrq_u32(bad, vorrq_u32(
                  vorrq_u32(sse_host_denormal_s(xv), sse_host_denormal_s(yv)),
                  vorrq_u32(sse_host_denormal_s(pv),
                            sse_host_denormal_s(sv))));
    }
    if (sticky && !(flags & float_flag_overflow)) {
        uint32x4_t fin = vandq_u32(
            vandq_u32(sse_host_finite_s(xv), sse_host_finite_s(yv)),
            vandq_u32(sse_host_finite_s(pv), sse_host_finite_s(tv)));
        bad = vorrq_u32(bad, vmvnq_u32(fin));
    }
    if (sticky && !(flags & float_flag_underflow)) {
        uint32x4_t nz = vandq_u32(sse_host_nonzero_s(xv),
                                  sse_host_nonzero_s(yv));
        bad = vorrq_u32(bad, vandq_u32(nz, sse_host_tiny_s(pv)));
    }
    if (sticky ? sse_host_any(bad)
               : !sse_host_finish(env, fpsr, sse_host_any(bad))) {
        return false;
    }
    memcpy(&bits, &t4, 4);
    for (int i = 0; i < 4; i++) {
        d[i] = (mask & (1 << i)) ? bits : 0;
    }
    return true;
}

/*
 * Conversions. Nearly all can be inexact, so the fast paths run only once PE
 * is set (see the top), and bail on any lane where the architectures could
 * differ: a NaN; a value outside the integer's range (x86 returns the
 * "integer indefinite", the most negative integer, and raises IE, where
 * AArch64 saturates); a denormal input while DE is clear or DAZ is set (DE,
 * and the zero a flushed input becomes); and for float64 to float32, an
 * overflow or a tiny result while OE or UE is clear, as for arithmetic.
 * Those that round need MXCSR at round-to-nearest; the truncating ones and
 * the exact ones (widening, int32 to float64) work in any mode.
 */
static inline bool sse_host_cvt_ok(CPUX86State *env, bool rounds)
{
    return (sse_host_flags(env) & float_flag_inexact) &&
           (!rounds || sse_host_mode_ok(env));
}

/* Whether a denormal input needs no fallback: DE set, DAZ clear. */
static inline bool sse_host_den_ok(CPUX86State *env)
{
    return (sse_host_flags(env) & float_flag_input_denormal_used) &&
           !env->sse_status.flush_inputs_to_zero;
}

/* cvtps2dq, cvttps2dq: 4 or 8 float32 to int32. */
static inline bool sse_host_cvtps2dq(CPUX86State *env, int32_t *d,
                                     const float32 *s, int lanes, bool trunc)
{
    bool den = !sse_host_den_ok(env);
    uint32x4_t bad = vdupq_n_u32(0);
    int32x4_t r[2];

    if (!sse_host_cvt_ok(env, !trunc)) {
        return false;
    }
    for (int i = 0; i < lanes / 4; i++) {
        float32x4_t x = vld1q_f32((const float *)s + 4 * i);
        /* -2^31 <= x < 2^31, false for a NaN */
        uint32x4_t in = vandq_u32(vcgeq_f32(x, vdupq_n_f32(-2147483648.0f)),
                                  vcltq_f32(x, vdupq_n_f32(2147483648.0f)));

        bad = vorrq_u32(bad, vmvnq_u32(in));
        if (den) {
            bad = vorrq_u32(bad, sse_host_denormal_s(x));
        }
        r[i] = trunc ? vcvtq_s32_f32(x) : vcvtnq_s32_f32(x);
    }
    if (sse_host_any(bad)) {
        return false;
    }
    for (int i = 0; i < lanes / 4; i++) {
        vst1q_s32(d + 4 * i, r[i]);
    }
    return true;
}

/* cvtpd2dq, cvttpd2dq: 2 or 4 float64 to int32 (the upper half is the caller's). */
static inline bool sse_host_cvtpd2dq(CPUX86State *env, int32_t *d,
                                     const float64 *s, int lanes, bool trunc)
{
    bool den = !sse_host_den_ok(env);
    uint32x4_t bad = vdupq_n_u32(0);
    int32x2_t r[2];

    if (!sse_host_cvt_ok(env, !trunc)) {
        return false;
    }
    for (int i = 0; i < lanes / 2; i++) {
        float64x2_t x = vld1q_f64((const double *)s + 2 * i);
        /* within range for either rounding; false for a NaN */
        uint64x2_t in = vandq_u64(vcgeq_f64(x, vdupq_n_f64(-2147483648.0)),
                                  vcleq_f64(x, vdupq_n_f64(2147483647.0)));

        bad = vorrq_u32(bad, vmvnq_u32(vreinterpretq_u32_u64(in)));
        if (den) {
            bad = vorrq_u32(bad, sse_host_denormal_d(x));
        }
        r[i] = vmovn_s64(trunc ? vcvtq_s64_f64(x) : vcvtnq_s64_f64(x));
    }
    if (sse_host_any(bad)) {
        return false;
    }
    for (int i = 0; i < lanes / 2; i++) {
        vst1_s32(d + 2 * i, r[i]);
    }
    return true;
}

static inline bool sse_host_denormal_bits_s(float32 x)
{
    return !(x & 0x7f800000) && (x & 0x007fffff);
}

static inline bool sse_host_denormal_bits_d(float64 x)
{
    return !(x & 0x7ff0000000000000ull) && (x & 0x000fffffffffffffull);
}

/*
 * The scalar float to int32/int64 forms, on the value widened (exactly) to
 * double; `den` says whether the original was denormal.
 */
static inline bool sse_host_f2i(CPUX86State *env, int64_t *r, double x,
                                bool den, bool is64, bool trunc)
{
    bool in = is64 ? x >= -9223372036854775808.0 && x < 9223372036854775808.0
                   : x >= -2147483648.0 && x <= 2147483647.0;

    if (!sse_host_cvt_ok(env, !trunc) || !in ||
        (den && !sse_host_den_ok(env))) {
        return false;
    }
    *r = trunc ? (int64_t)x : vcvtnd_s64_f64(x);
    return true;
}

static inline bool sse_host_ss2si(CPUX86State *env, int64_t *r, float32 a,
                                  bool is64, bool trunc)
{
    float x;

    memcpy(&x, &a, 4);
    return sse_host_f2i(env, r, x, sse_host_denormal_bits_s(a), is64, trunc);
}

static inline bool sse_host_sd2si(CPUX86State *env, int64_t *r, float64 a,
                                  bool is64, bool trunc)
{
    double x;

    memcpy(&x, &a, 8);
    return sse_host_f2i(env, r, x, sse_host_denormal_bits_d(a), is64, trunc);
}

/* cvtdq2ps: 4 or 8 int32 to float32; exact up to 2^24. */
static inline bool sse_host_cvtdq2ps(CPUX86State *env, float32 *d,
                                     const int32_t *s, int lanes)
{
    uint32x4_t big = vdupq_n_u32(0);
    float32x4_t r[2];

    if (!sse_host_mode_ok(env)) {
        return false;
    }
    for (int i = 0; i < lanes / 4; i++) {
        int32x4_t x = vld1q_s32(s + 4 * i);

        big = vorrq_u32(big, vcgtq_u32(vreinterpretq_u32_s32(vabsq_s32(x)),
                                       vdupq_n_u32(1 << 24)));
        r[i] = vcvtq_f32_s32(x);
    }
    if (sse_host_any(big) && !(sse_host_flags(env) & float_flag_inexact)) {
        return false;
    }
    for (int i = 0; i < lanes / 4; i++) {
        vst1q_f32((float *)d + 4 * i, r[i]);
    }
    return true;
}

/* cvtdq2pd: 2 or 4 int32 to float64, always exact. */
static inline bool sse_host_cvtdq2pd(float64 *d, const int32_t *s, int lanes)
{
    float64x2_t r[2];

    for (int i = 0; i < lanes / 2; i++) {
        r[i] = vcvtq_f64_s64(vmovl_s32(vld1_s32(s + 2 * i)));
    }
    for (int i = 0; i < lanes / 2; i++) {
        vst1q_f64((double *)d + 2 * i, r[i]);
    }
    return true;
}

/* cvtsi2ss, cvtsq2ss, cvtsq2sd: exact if the integer fits the significand. */
static inline bool sse_host_i2f_ok(CPUX86State *env, int64_t v, int bits)
{
    uint64_t m = v < 0 ? -(uint64_t)v : v;

    return sse_host_mode_ok(env) &&
           (m <= (1ull << bits) || (sse_host_flags(env) & float_flag_inexact));
}

/* cvtps2pd: 2 or 4 float32 to float64; exact, so any mode. */
static inline bool sse_host_cvtps2pd(CPUX86State *env, float64 *d,
                                     const float32 *s, int lanes)
{
    bool den = !sse_host_den_ok(env);
    uint32x4_t bad = vdupq_n_u32(0);
    float64x2_t r[2];

    for (int i = 0; i < lanes / 2; i++) {
        float32x2_t x = vld1_f32((const float *)s + 2 * i);
        float32x4_t xq = vcombine_f32(x, x);

        bad = vorrq_u32(bad, sse_host_nan_s(xq));
        if (den) {
            bad = vorrq_u32(bad, sse_host_denormal_s(xq));
        }
        r[i] = vcvt_f64_f32(x);
    }
    if (sse_host_any(bad)) {
        return false;
    }
    for (int i = 0; i < lanes / 2; i++) {
        vst1q_f64((double *)d + 2 * i, r[i]);
    }
    return true;
}

/* cvtpd2ps: 2 or 4 float64 to float32 (the upper half is the caller's). */
static inline bool sse_host_cvtpd2ps(CPUX86State *env, float32 *d,
                                     const float64 *s, int lanes)
{
    int flags = sse_host_flags(env);
    bool den = !sse_host_den_ok(env);
    uint32x4_t bad = vdupq_n_u32(0);
    float32x2_t r[2];

    if (!sse_host_cvt_ok(env, true)) {
        return false;
    }
    for (int i = 0; i < lanes / 2; i++) {
        float64x2_t x = vld1q_f64((const double *)s + 2 * i);
        float32x2_t y = vcvt_f32_f64(x);
        float32x4_t yq = vcombine_f32(y, y);
        /* the float64 checks give two 64-bit lanes; line them up with y's */
        uint32x4_t nz = vreinterpretq_u32_u64(vtstq_u64(
            vreinterpretq_u64_f64(x), vdupq_n_u64(0x7fffffffffffffffull)));
        uint32x4_t fin = sse_host_finite_d(x);

        nz = vcombine_u32(vmovn_u64(vreinterpretq_u64_u32(nz)),
                          vmovn_u64(vreinterpretq_u64_u32(nz)));
        fin = vcombine_u32(vmovn_u64(vreinterpretq_u64_u32(fin)),
                           vmovn_u64(vreinterpretq_u64_u32(fin)));
        bad = vorrq_u32(bad, sse_host_nan_s(yq));
        if (den) {
            bad = vorrq_u32(bad, sse_host_denormal_d(x));
        }
        if (!(flags & float_flag_overflow)) {
            bad = vorrq_u32(bad, vbicq_u32(fin, sse_host_finite_s(yq)));
        }
        if (!(flags & float_flag_underflow)) {
            bad = vorrq_u32(bad, vandq_u32(nz, sse_host_tiny_s(yq)));
        }
        r[i] = y;
    }
    if (sse_host_any(bad)) {
        return false;
    }
    for (int i = 0; i < lanes / 2; i++) {
        vst1_f32((float *)d + 2 * i, r[i]);
    }
    return true;
}

/*
 * Integer shuffles, packs and blends: pure data movement, exact by
 * construction, and independent of MXCSR. Each works on the register's
 * 128-bit lanes (one for SSE, two for AVX2, which permutes within lanes),
 * loading every input before storing, as the destination may alias one.
 */
static inline uint8x16_t sse_host_ld8(const void *p, int lane)
{
    return vld1q_u8((const uint8_t *)p + 16 * lane);
}

static inline void sse_host_st8(void *p, int lane, uint8x16_t x)
{
    vst1q_u8((uint8_t *)p + 16 * lane, x);
}

/* pshufb: a byte index with bit 7 set gives 0, which TBL does for >= 16. */
static inline bool sse_host_pshufb(void *d, const void *v, const void *s,
                                   int lanes)
{
    uint8x16_t r[2];

    for (int i = 0; i < lanes; i++) {
        r[i] = vqtbl1q_u8(sse_host_ld8(v, i),
                          vandq_u8(sse_host_ld8(s, i), vdupq_n_u8(0x8f)));
    }
    for (int i = 0; i < lanes; i++) {
        sse_host_st8(d, i, r[i]);
    }
    return true;
}

/*
 * pblendvb, blendvps, blendvpd: s where the mask element's top bit is set,
 * else v. `size` is the element size in bytes.
 */
static inline bool sse_host_blendv(void *d, const void *v, const void *s,
                                   const void *m, int lanes, int size)
{
    uint8x16_t r[2];

    for (int i = 0; i < lanes; i++) {
        uint8x16_t mm = sse_host_ld8(m, i);
        uint8x16_t sel;

        switch (size) {
        case 1:
            sel = vreinterpretq_u8_s8(vshrq_n_s8(vreinterpretq_s8_u8(mm), 7));
            break;
        case 4:
            sel = vreinterpretq_u8_s32(
                vshrq_n_s32(vreinterpretq_s32_u8(mm), 31));
            break;
        default:
            sel = vreinterpretq_u8_s64(
                vshrq_n_s64(vreinterpretq_s64_u8(mm), 63));
            break;
        }
        r[i] = vbslq_u8(sel, sse_host_ld8(s, i), sse_host_ld8(v, i));
    }
    for (int i = 0; i < lanes; i++) {
        sse_host_st8(d, i, r[i]);
    }
    return true;
}

/* The packs: v's elements narrowed, then s's, per lane, saturating. */

static inline bool sse_host_pack(void *d, const void *v, const void *s,
                                 int lanes, int op)
{
    uint8x16_t r[2];

    for (int i = 0; i < lanes; i++) {
        uint8x16_t a = sse_host_ld8(v, i), b = sse_host_ld8(s, i);

        switch (op) {
        case SSE_HOST_PACKSSWB:
            r[i] = vreinterpretq_u8_s8(vcombine_s8(
                vqmovn_s16(vreinterpretq_s16_u8(a)),
                vqmovn_s16(vreinterpretq_s16_u8(b))));
            break;
        case SSE_HOST_PACKUSWB:
            r[i] = vcombine_u8(vqmovun_s16(vreinterpretq_s16_u8(a)),
                               vqmovun_s16(vreinterpretq_s16_u8(b)));
            break;
        case SSE_HOST_PACKSSDW:
            r[i] = vreinterpretq_u8_s16(vcombine_s16(
                vqmovn_s32(vreinterpretq_s32_u8(a)),
                vqmovn_s32(vreinterpretq_s32_u8(b))));
            break;
        default:
            r[i] = vreinterpretq_u8_u16(vcombine_u16(
                vqmovun_s32(vreinterpretq_s32_u8(a)),
                vqmovun_s32(vreinterpretq_s32_u8(b))));
            break;
        }
    }
    for (int i = 0; i < lanes; i++) {
        sse_host_st8(d, i, r[i]);
    }
    return true;
}

/*
 * punpckl* and punpckh*: the low or high halves of v and s, interleaved
 * v first; `size` is the element size in bytes.
 */
static inline bool sse_host_unpck(void *d, const void *v, const void *s,
                                  int lanes, int size, bool high)
{
    uint8x16_t r[2];

    for (int i = 0; i < lanes; i++) {
        uint8x16_t a = sse_host_ld8(v, i), b = sse_host_ld8(s, i);

        switch (size) {
        case 1:
            r[i] = high ? vzip2q_u8(a, b) : vzip1q_u8(a, b);
            break;
        case 2:
            r[i] = vreinterpretq_u8_u16(
                high ? vzip2q_u16(vreinterpretq_u16_u8(a),
                                  vreinterpretq_u16_u8(b))
                     : vzip1q_u16(vreinterpretq_u16_u8(a),
                                  vreinterpretq_u16_u8(b)));
            break;
        case 4:
            r[i] = vreinterpretq_u8_u32(
                high ? vzip2q_u32(vreinterpretq_u32_u8(a),
                                  vreinterpretq_u32_u8(b))
                     : vzip1q_u32(vreinterpretq_u32_u8(a),
                                  vreinterpretq_u32_u8(b)));
            break;
        default:
            r[i] = vreinterpretq_u8_u64(
                high ? vzip2q_u64(vreinterpretq_u64_u8(a),
                                  vreinterpretq_u64_u8(b))
                     : vzip1q_u64(vreinterpretq_u64_u8(a),
                                  vreinterpretq_u64_u8(b)));
            break;
        }
    }
    for (int i = 0; i < lanes; i++) {
        sse_host_st8(d, i, r[i]);
    }
    return true;
}

/*
 * palignr: per lane, the 32 bytes s:v (s low) shifted right by imm bytes.
 * The shift is not a constant, so a two-register TBL does it: indices of
 * 32 and above give 0, as the shift brings in. imm >= 32 is the caller's.
 */
static inline bool sse_host_palignr(void *d, const void *v, const void *s,
                                    int lanes, uint32_t imm)
{
    static const uint8_t iota[16] = { 0, 1, 2, 3, 4, 5, 6, 7,
                                      8, 9, 10, 11, 12, 13, 14, 15 };
    uint8x16_t idx = vaddq_u8(vld1q_u8(iota), vdupq_n_u8(imm));
    uint8x16_t r[2];

    for (int i = 0; i < lanes; i++) {
        uint8x16x2_t t = { { sse_host_ld8(s, i), sse_host_ld8(v, i) } };

        r[i] = vqtbl2q_u8(t, idx);
    }
    for (int i = 0; i < lanes; i++) {
        sse_host_st8(d, i, r[i]);
    }
    return true;
}

/*
 * pmovzx* and pmovsx*: the low elements of s widened from `from` to `to`
 * bytes, filling the destination (128 or 256 bits, not per lane).
 */
static inline bool sse_host_pmovx(void *d, const void *s, int bytes,
                                  int from, int to, bool sign)
{
    uint8_t in[32] = { 0 };   /* room for the second half's 16-byte load */
    uint8x16_t r[2];
    int n = bytes / to;   /* elements out */

    memcpy(in, s, n * from);
    for (int half = 0; half < bytes / 16; half++) {
        /* the source bytes this half of the result widens */
        uint8x16_t x = vld1q_u8(in + half * (16 / to) * from);

        for (int w = from; w < to; w *= 2) {
            switch (w) {
            case 1:
                x = sign ? vreinterpretq_u8_s16(vmovl_s8(vget_low_s8(
                               vreinterpretq_s8_u8(x))))
                         : vreinterpretq_u8_u16(vmovl_u8(vget_low_u8(x)));
                break;
            case 2:
                x = sign ? vreinterpretq_u8_s32(vmovl_s16(vget_low_s16(
                               vreinterpretq_s16_u8(x))))
                         : vreinterpretq_u8_u32(vmovl_u16(vget_low_u16(
                               vreinterpretq_u16_u8(x))));
                break;
            default:
                x = sign ? vreinterpretq_u8_s64(vmovl_s32(vget_low_s32(
                               vreinterpretq_s32_u8(x))))
                         : vreinterpretq_u8_u64(vmovl_u32(vget_low_u32(
                               vreinterpretq_u32_u8(x))));
                break;
            }
        }
        r[half] = x;
    }
    for (int half = 0; half < bytes / 16; half++) {
        sse_host_st8(d, half, r[half]);
    }
    return true;
}

#else

#define sse_host_ps(...) false
#define sse_host_pd(...) false
#define sse_host_ss(...) false
#define sse_host_sd(...) false
#define sse_host_minmax_ps(...) false
#define sse_host_minmax_pd(...) false
#define sse_host_minmax_ss(...) false
#define sse_host_minmax_sd(...) false
#define sse_host_plain_ps(...) false
#define sse_host_plain_pd(...) false
#define sse_host_plain_s(...) false
#define sse_host_plain_d(...) false
#define sse_host_rel_s(a, b) float_relation_unordered
#define sse_host_rel_d(a, b) float_relation_unordered
#define sse_host_fma_ps(...) false
#define sse_host_fma_pd(...) false
#define sse_host_fma_ss(...) false
#define sse_host_fma_sd(...) false
#define sse_host_dpps(...) false
#define sse_host_cvtps2dq(...) false
#define sse_host_cvtpd2dq(...) false
#define sse_host_ss2si(...) false
#define sse_host_sd2si(...) false
#define sse_host_cvtdq2ps(...) false
#define sse_host_cvtdq2pd(...) false
#define sse_host_i2f_ok(...) false
#define sse_host_cvtps2pd(...) false
#define sse_host_cvtpd2ps(...) false
#define sse_host_pshufb(...) false
#define sse_host_blendv(...) false
#define sse_host_pack(...) false
#define sse_host_unpck(...) false
#define sse_host_palignr(...) false
#define sse_host_pmovx(...) false

#endif /* __aarch64__ */

#endif /* TARGET_I386_OPS_SSE_HOST_H */
