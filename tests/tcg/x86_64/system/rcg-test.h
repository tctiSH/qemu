/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * What rcg-insns and rcg-faults share: running one instruction from a
 * register and flags state set up in memory, and catching exceptions.
 *
 * Each case is an instruction that target/i386/tcg/rcg-gen.py writes out
 * with RCG_CASE(), from the same tables it makes RCG's gadgets from. A
 * case's functions load every register, RSP included, and the flags from
 * rcg_in, run the instruction, and store them all to rcg_out, with the
 * results of SETcc for every condition. They keep the caller's registers.
 *
 * The data the instructions use is at fixed addresses, mapped one to one by
 * boot.S, so that addresses in what the tests compare do not move with the
 * test binary's layout. rcg-gen.py reads them from the defines below.
 */

#ifndef RCG_TEST_H
#define RCG_TEST_H

#include <minilib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The memory operand's 64 bytes, and the stack's, 64 bytes on each side of
 * where RSP starts. rcg-gen.py places each case's memory operand and RSP in
 * them. They are above the test binary, which rcg_init() checks, and below
 * rcg-faults' pages.
 *
 * RCG_MEM is also rcg_mem, which the cases' RIP-relative operands name. The
 * Makefile defines it when linking: defined here, it would be absolute, and
 * the assembler would make [rip+rcg_mem] RIP plus its address.
 */
#define RCG_MEM 0x1800000
#define RCG_MEM_SIZE 64
#define RCG_STACK 0x1801000
#define RCG_STACK_SIZE 64

/*
 * rcg_init() maps the 2 MiB from RCG_HI, above 4 GiB, to the 2 MiB from
 * RCG_MEM. Most cases reach their memory operand and stack through RCG_HI,
 * so that an address computed in 32 bits lands elsewhere.
 */
#define RCG_HI 0x100000000

/* Where a branch in rcg-faults finds its target, if not in a register. */
#define RCG_TARGET_MEM 0x10
#define RCG_TARGET_STACK 0x11

/* What the cases with a segment override find in FS's and GS's bases. */
#define RCG_FS_BASE 0x1000
#define RCG_GS_BASE 0x2000

/* The arithmetic flags: CF, PF, AF, ZF, SF and OF. */
#define RCG_FLAGS 0x8d5ul

#define R_ESP 4

/*
 * The registers, the flags, SETcc's result for each condition, XMM0 to
 * XMM3, as two 64-bit halves each, and MXCSR.
 */
struct rcg_state {
    uint64_t r[16];
    uint64_t flags;
    uint8_t cc[16];
    uint64_t x[4][2];
    uint32_t mxcsr;
};

/* Where rcg_enter and rcg_leave find x and mxcsr. */
_Static_assert(offsetof(struct rcg_state, x) == 152, "x moved");
_Static_assert(offsetof(struct rcg_state, mxcsr) == 216, "mxcsr moved");

/*
 * A case's xmm: 0 if it uses no XMM register, 1 if it uses XMM0 to XMM3
 * with the integer values, or one of these with floating-point values in
 * their lanes, doubles or floats, and MXCSR from the start.
 */
#define RCG_XMM_F64 2
#define RCG_XMM_F32 3
/*
 * The same with normal values only, from rcg_f64n and rcg_f32n, so that
 * every lane of a packed operand can take the host's FPU in the gadgets.
 */
#define RCG_XMM_F64N 4
#define RCG_XMM_F32N 5

struct rcg_state rcg_in, rcg_out, rcg_host;

/*
 * What a case's _sub function compares with 1 before the instruction, and
 * its _adc function adds 1 to.
 */
uint64_t rcg_sub_in;

/*
 * A case, as rcg-gen.py describes it. fn runs the instruction from the
 * flags in rcg_in, fn_sub from the state a CMP leaves (see rcg_starts), and
 * fn_adc, which only rcg-faults has, from the state an ADC leaves; insn,
 * insn_sub and insn_adc are where the instruction is in each, and end,
 * end_sub and end_adc where it ends.
 *
 * The registers a and b take the values tested (b may be the memory
 * operand instead, mem), and base and index make the memory operand's
 * address, with base_value and index_value. The memory operand is at
 * operand, and RSP starts at rsp. stack says the instruction uses the
 * stack. moved is the register rcg-faults moves across a page boundary,
 * and writes says that the access there writes memory. target is where
 * rcg-faults puts the address of the instruction's end for a branch: a
 * register, RCG_TARGET_MEM (the memory operand) or RCG_TARGET_STACK (the
 * top of the stack). -1 is no register. xmm says that the case uses XMM0
 * to XMM3 (see RCG_XMM_F64), which rcg-insns then compares too. aligned
 * says that its access must be on a 16-byte boundary, for rcg-faults.
 */
struct rcg_case {
    const char *name;
    void (*fn)(void);
    const char *insn, *end;
    void (*fn_sub)(void);
    const char *insn_sub, *end_sub;
    void (*fn_adc)(void);
    const char *insn_adc, *end_adc;
    int width;
    int a, b;
    bool mem;
    int base, index;
    uint64_t base_value;
    int64_t index_value;
    bool stack;
    bool writes;
    uint64_t operand, rsp;
    int moved;
    int target;
    uint8_t xmm;
    bool aligned;
};

asm(
    /*
     * Keep the caller's registers, then load the case's, with XMM0 to XMM3 if
     * xmm is not 0, and MXCSR too with floating-point values. POPF ends the
     * TB, so the case's instruction starts the next one. The code from the
     * XMM loads to the RET starts on a 512 byte boundary and fits in 512
     * bytes, so that the instruction and the SETcc after it are never split
     * across a page, which would end the TB between them. The XMM loads and
     * stores are left out of the other cases to keep that true.
     */
    "    .macro rcg_enter xmm\n"
    "    mov %rbx, rcg_host+3*8(%rip)\n"
    "    mov %rsp, rcg_host+4*8(%rip)\n"
    "    mov %rbp, rcg_host+5*8(%rip)\n"
    "    mov %r12, rcg_host+12*8(%rip)\n"
    "    mov %r13, rcg_host+13*8(%rip)\n"
    "    mov %r14, rcg_host+14*8(%rip)\n"
    "    mov %r15, rcg_host+15*8(%rip)\n"
    "    pushq rcg_in+16*8(%rip)\n"
    "    .balign 512\n"
    "    .if \\xmm\n"
    "    movdqu rcg_in+152(%rip), %xmm0\n"
    "    movdqu rcg_in+168(%rip), %xmm1\n"
    "    movdqu rcg_in+184(%rip), %xmm2\n"
    "    movdqu rcg_in+200(%rip), %xmm3\n"
    "    .ifge \\xmm-2\n"
    "    ldmxcsr rcg_in+216(%rip)\n"
    "    .endif\n"
    "    .endif\n"
    "    popfq\n"
    "    mov rcg_in+0*8(%rip), %rax\n"
    "    mov rcg_in+1*8(%rip), %rcx\n"
    "    mov rcg_in+2*8(%rip), %rdx\n"
    "    mov rcg_in+3*8(%rip), %rbx\n"
    "    mov rcg_in+4*8(%rip), %rsp\n"
    "    mov rcg_in+5*8(%rip), %rbp\n"
    "    mov rcg_in+6*8(%rip), %rsi\n"
    "    mov rcg_in+7*8(%rip), %rdi\n"
    "    mov rcg_in+8*8(%rip), %r8\n"
    "    mov rcg_in+9*8(%rip), %r9\n"
    "    mov rcg_in+10*8(%rip), %r10\n"
    "    mov rcg_in+11*8(%rip), %r11\n"
    "    mov rcg_in+12*8(%rip), %r12\n"
    "    mov rcg_in+13*8(%rip), %r13\n"
    "    mov rcg_in+14*8(%rip), %r14\n"
    "    mov rcg_in+15*8(%rip), %r15\n"
    "    .endm\n"

    /*
     * Store SETcc's results, the case's registers and flags, which SETcc
     * and MOV do not change, and XMM0 to XMM3 if xmm is not 0, with MXCSR
     * for floating-point values. Then return with the caller's registers.
     */
    "    .macro rcg_leave xmm\n"
    "    seto rcg_out+17*8+0(%rip)\n"
    "    setno rcg_out+17*8+1(%rip)\n"
    "    setb rcg_out+17*8+2(%rip)\n"
    "    setae rcg_out+17*8+3(%rip)\n"
    "    sete rcg_out+17*8+4(%rip)\n"
    "    setne rcg_out+17*8+5(%rip)\n"
    "    setbe rcg_out+17*8+6(%rip)\n"
    "    seta rcg_out+17*8+7(%rip)\n"
    "    sets rcg_out+17*8+8(%rip)\n"
    "    setns rcg_out+17*8+9(%rip)\n"
    "    setp rcg_out+17*8+10(%rip)\n"
    "    setnp rcg_out+17*8+11(%rip)\n"
    "    setl rcg_out+17*8+12(%rip)\n"
    "    setge rcg_out+17*8+13(%rip)\n"
    "    setle rcg_out+17*8+14(%rip)\n"
    "    setg rcg_out+17*8+15(%rip)\n"
    "    mov %rsp, rcg_out+4*8(%rip)\n"
    "    mov rcg_host+4*8(%rip), %rsp\n"
    "    pushfq\n"
    "    popq rcg_out+16*8(%rip)\n"
    "    mov %rax, rcg_out+0*8(%rip)\n"
    "    mov %rcx, rcg_out+1*8(%rip)\n"
    "    mov %rdx, rcg_out+2*8(%rip)\n"
    "    mov %rbx, rcg_out+3*8(%rip)\n"
    "    mov %rbp, rcg_out+5*8(%rip)\n"
    "    mov %rsi, rcg_out+6*8(%rip)\n"
    "    mov %rdi, rcg_out+7*8(%rip)\n"
    "    mov %r8, rcg_out+8*8(%rip)\n"
    "    mov %r9, rcg_out+9*8(%rip)\n"
    "    mov %r10, rcg_out+10*8(%rip)\n"
    "    mov %r11, rcg_out+11*8(%rip)\n"
    "    mov %r12, rcg_out+12*8(%rip)\n"
    "    mov %r13, rcg_out+13*8(%rip)\n"
    "    mov %r14, rcg_out+14*8(%rip)\n"
    "    mov %r15, rcg_out+15*8(%rip)\n"
    "    .if \\xmm\n"
    "    movdqu %xmm0, rcg_out+152(%rip)\n"
    "    movdqu %xmm1, rcg_out+168(%rip)\n"
    "    movdqu %xmm2, rcg_out+184(%rip)\n"
    "    movdqu %xmm3, rcg_out+200(%rip)\n"
    "    .ifge \\xmm-2\n"
    "    stmxcsr rcg_out+216(%rip)\n"
    "    .endif\n"
    "    .endif\n"
    "    mov rcg_host+3*8(%rip), %rbx\n"
    "    mov rcg_host+5*8(%rip), %rbp\n"
    "    mov rcg_host+12*8(%rip), %r12\n"
    "    mov rcg_host+13*8(%rip), %r13\n"
    "    mov rcg_host+14*8(%rip), %r14\n"
    "    mov rcg_host+15*8(%rip), %r15\n"
    "    ret\n"
    "    .endm\n");

/*
 * A case's functions, name and name_sub, and the labels of the instruction
 * in each, name_insn and name_sub_insn, which is where an exception the
 * instruction raises points, and of its end, name_end and name_sub_end.
 * name_sub compares rcg_sub_in with 1 first, after loading the registers,
 * so that the instruction runs from the state a SUB leaves, in the same TB.
 * xmm is the case's xmm (see RCG_XMM_F64).
 */
#define RCG_CASE(name, insn, xmm)                               \
    void name(void);                                            \
    void name##_sub(void);                                      \
    extern const char name##_insn[], name##_end[];              \
    extern const char name##_sub_insn[], name##_sub_end[];      \
    asm("    .pushsection .text\n"                              \
        #name ":\n"                                             \
        "    rcg_enter " #xmm "\n"                              \
        "    .intel_syntax noprefix\n"                          \
        #name "_insn:\n"                                        \
        "    " insn "\n"                                        \
        #name "_end:\n"                                         \
        "    .att_syntax prefix\n"                              \
        "    rcg_leave " #xmm "\n"                              \
        #name "_sub:\n"                                         \
        "    rcg_enter " #xmm "\n"                              \
        "    cmpq $1, rcg_sub_in(%rip)\n"                       \
        "    .intel_syntax noprefix\n"                          \
        #name "_sub_insn:\n"                                    \
        "    " insn "\n"                                        \
        #name "_sub_end:\n"                                     \
        "    .att_syntax prefix\n"                              \
        "    rcg_leave " #xmm "\n"                              \
        "    .popsection\n");

/*
 * A case's function name_adc, with the labels name_adc_insn and
 * name_adc_end. It adds 1 to rcg_sub_in with ADC first, after loading the
 * registers, so that the instruction runs from the state an ADC leaves,
 * which uses cc_src2, in the same TB.
 */
#define RCG_ADC_CASE(name, insn, xmm)                           \
    void name##_adc(void);                                      \
    extern const char name##_adc_insn[], name##_adc_end[];      \
    asm("    .pushsection .text\n"                              \
        #name "_adc:\n"                                         \
        "    rcg_enter " #xmm "\n"                              \
        "    adcq $1, rcg_sub_in(%rip)\n"                       \
        "    .intel_syntax noprefix\n"                          \
        #name "_adc_insn:\n"                                    \
        "    " insn "\n"                                        \
        #name "_adc_end:\n"                                     \
        "    .att_syntax prefix\n"                              \
        "    rcg_leave " #xmm "\n"                              \
        "    .popsection\n");

/* The values every operand is tested with: the edges of each width. */
static const uint64_t rcg_values[] = {
    0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff,
    0x7fffffff, 0x80000000, 0xffffffff,
    0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff,
    0x0123456789abcdef, 0xfedcba9876543210,
};
#define RCG_NB_VALUES (sizeof(rcg_values) / sizeof(rcg_values[0]))

/*
 * What a case with floating-point values puts in its lanes for each of
 * rcg_values, by its place there: values whose sums and products stay
 * normal, and the edges, the largest and smallest normals, denormals,
 * zeros, infinities and NaNs, quiet and signaling. The value just below 1,
 * times the smallest normal, rounds up to the smallest normal and raises
 * UE; the last, squared, is near the smallest normal.
 */
static const uint64_t rcg_f64[] = {
    0x3ff0000000000000ull,  /* 1 */
    0xbff8000000000000ull,  /* -1.5 */
    0x400921fb54442d18ull,  /* pi */
    0x3fb999999999999aull,  /* 0.1 */
    0x7fefffffffffffffull,  /* the largest */
    0x0010000000000000ull,  /* the smallest normal */
    0x000fffffffffffffull,  /* the largest denormal */
    0x8000000000000001ull,  /* minus the smallest denormal */
    0x0000000000000000ull,  /* 0 */
    0x8000000000000000ull,  /* -0 */
    0x7ff0000000000000ull,  /* infinity */
    0xfff0000000000000ull,  /* minus infinity */
    0x7ff8000000000000ull,  /* a quiet NaN */
    0xfff4000000000000ull,  /* a signaling NaN */
    0x3fefffffffffffffull,  /* 1 - 2^-53 */
    0x2010000000000000ull,  /* 2^-510 */
};

static const uint32_t rcg_f32[] = {
    0x3f800000, 0xbfc00000, 0x40490fdb, 0x3dcccccd,
    0x7f7fffff, 0x00800000, 0x007fffff, 0x80000001,
    0x00000000, 0x80000000, 0x7f800000, 0xff800000,
    0x7fc00000, 0xffa00000,
    0x3f7fffff,             /* 1 - 2^-24 */
    0x20800000,             /* 2^-62 */
};

/*
 * Normal values only, for RCG_XMM_F64N and RCG_XMM_F32N: nearly every pair
 * gives a normal result, and the largest and smallest normals make some
 * overflow or underflow.
 */
static const uint64_t rcg_f64n[] = {
    0x3ff0000000000000ull,  /* 1 */
    0xbff8000000000000ull,  /* -1.5 */
    0x400921fb54442d18ull,  /* pi */
    0x3fb999999999999aull,  /* 0.1 */
    0x4202a05f20000000ull,  /* 1e10 */
    0xbeff75104d551d69ull,  /* -3e-5 */
    0x4000000000000000ull,  /* 2 */
    0x3fe8000000000000ull,  /* 0.75 */
    0x3fefffffffffffffull,  /* 1 - 2^-53 */
    0x401c000000000000ull,  /* 7 */
    0x0010000000000000ull,  /* the smallest normal */
    0x3bc79ca10c924223ull,  /* 1e-20 */
    0x54b249ad2594c37dull,  /* 1e100 */
    0x7fefffffffffffffull,  /* the largest */
    0x20b0000000000000ull,  /* 2^-500 */
    0x44dfde9f10a8d361ull,  /* 6.02e23 */
};

static const uint32_t rcg_f32n[] = {
    0x3f800000, 0xbfc00000, 0x40490fdb, 0x3dcccccd,
    0x49742400,             /* 1e6 */
    0xb7fba882,             /* -3e-5 */
    0x40000000, 0x3f400000,
    0x3f7fffff,             /* 1 - 2^-24 */
    0x40e00000,
    0x00800000,             /* the smallest normal */
    0x358637bd,             /* 1e-6 */
    0x4640e6b6,             /* 12345.678 */
    0x7f7fffff,             /* the largest */
    0x21800000,             /* 2^-60 */
    0x4912f900,             /* 602000 */
};

_Static_assert(sizeof(rcg_f64) / sizeof(rcg_f64[0]) == RCG_NB_VALUES &&
               sizeof(rcg_f32) / sizeof(rcg_f32[0]) == RCG_NB_VALUES &&
               sizeof(rcg_f64n) / sizeof(rcg_f64n[0]) == RCG_NB_VALUES &&
               sizeof(rcg_f32n) / sizeof(rcg_f32n[0]) == RCG_NB_VALUES,
               "a floating-point value for each value");

/* v's place in rcg_values, or for another value one picked from its bits. */
static inline int rcg_value_index(uint64_t v)
{
    for (int i = 0; i < RCG_NB_VALUES; i++) {
        if (rcg_values[i] == v) {
            return i;
        }
    }
    return (v ^ v >> 29) % RCG_NB_VALUES;
}

/* 64 bits of lanes for case c: value k, then for floats k + 7. */
static inline uint64_t rcg_fp_bits(const struct rcg_case *c, int k)
{
    bool normal = c->xmm >= RCG_XMM_F64N;
    const uint32_t *f32 = normal ? rcg_f32n : rcg_f32;

    if (c->xmm == RCG_XMM_F64 || c->xmm == RCG_XMM_F64N) {
        return (normal ? rcg_f64n : rcg_f64)[k % RCG_NB_VALUES];
    }
    return f32[k % RCG_NB_VALUES] |
           (uint64_t)f32[(k + 7) % RCG_NB_VALUES] << 32;
}

/*
 * The states each case starts from. The first two load the flags with
 * POPF, the arithmetic ones clear and then set, which leaves CC_OP_EFLAGS.
 * The rest then compare sub_in with 1, leaving a SUB state with cc_dst,
 * cc_src and the first operand live. That shows when an instruction that
 * should leave the flags alone does not. The values give a borrow (CF and
 * SF), a signed overflow (OF) and equality (ZF). adc instead adds 1 to
 * sub_in with ADC (see RCG_ADC_CASE()), which only rcg-faults does. fp
 * says that only the cases with floating-point values start from it.
 */
struct rcg_start {
    uint64_t flags;
    bool sub;
    uint64_t sub_in;
    bool adc;
    uint32_t mxcsr;
    bool fp;
};

/*
 * For the cases with floating-point values, each start also loads MXCSR:
 * the default; with PE set, as it nearly always is once a program runs;
 * then with PE and each of FZ, rounding down, DAZ and rounding up; and
 * with all six exception flags set, from which the gadgets also take the
 * fast path, and which they must leave set.
 */
static const struct rcg_start rcg_starts[] = {
    { 0x2, false, 0, false, 0x1f80 },
    { 0x2 | RCG_FLAGS, false, 0, false, 0x1fa0 },
    { 0x2, true, 0, false, 0x9fa0 },
    { 0x2, true, 0x8000000000000000ull, false, 0x3fa0 },
    { 0x2, true, 1, false, 0x1fe0 },
    { 0x2, true, 0x8000000000000000ull, false, 0x5fa0, true },
    { 0x2, true, 1, false, 0x1fbf, true },
};
#define RCG_NB_STARTS (sizeof(rcg_starts) / sizeof(rcg_starts[0]))

/* Runs case c from the start s, set up with rcg_setup(). */
static inline void rcg_run(const struct rcg_case *c, const struct rcg_start *s)
{
    (s->adc ? c->fn_adc : s->sub ? c->fn_sub : c->fn)();
}

/* The address of the instruction rcg_run() runs. */
static inline uint64_t rcg_insn_addr(const struct rcg_case *c,
                                     const struct rcg_start *s)
{
    return (uint64_t)(s->adc ? c->insn_adc : s->sub ? c->insn_sub : c->insn);
}

/* The address of the end of the instruction rcg_run() runs. */
static inline uint64_t rcg_insn_end(const struct rcg_case *c,
                                    const struct rcg_start *s)
{
    return (uint64_t)(s->adc ? c->end_adc : s->sub ? c->end_sub : c->end);
}

static inline uint8_t *rcg_bytes(uint64_t addr)
{
    return (uint8_t *)addr;
}

static inline void rcg_store64(uint64_t addr, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        rcg_bytes(addr)[i] = v >> (i * 8);
    }
}

/* Fills n bytes at addr with a pattern that marks each byte. */
static inline void rcg_fill(uint64_t addr, int n, uint8_t seed)
{
    for (int i = 0; i < n; i++) {
        rcg_bytes(addr)[i] = seed + i * 0x3b;
    }
}

/*
 * Stores the floating-point values for y at addr, for case c's memory
 * operand: 16 bytes, of which a scalar case reads the first 4 or 8.
 */
static inline void rcg_store_fp(const struct rcg_case *c, uint64_t addr,
                                uint64_t y)
{
    int j = rcg_value_index(y);

    rcg_store64(addr, rcg_fp_bits(c, j));
    rcg_store64(addr + 8, rcg_fp_bits(c, j + 9));
}

/*
 * Sets rcg_in up for case c with the values x (for a) and y (for b, the
 * memory operand or the top of the stack) and the start s, the memory
 * around the operand and the stack included. Every other register gets a
 * different value, so that a write to one shows.
 */
static inline void rcg_setup(const struct rcg_case *c, uint64_t x, uint64_t y,
                             const struct rcg_start *s)
{
    for (int i = 0; i < 16; i++) {
        rcg_in.r[i] = 0x1111111111111111ull * (i + 1) ^ 0x8040201008040201ull;
    }
    rcg_in.r[R_ESP] = c->rsp;
    for (int i = 0; i < 4; i++) {
        rcg_in.x[i][0] = x ^ 0x0101010101010101ull * (i + 1);
        rcg_in.x[i][1] = y ^ 0x1010101010101010ull * (i + 1);
    }
    rcg_in.mxcsr = 0x1f80;
    if (c->xmm >= RCG_XMM_F64) {
        /*
         * XMM1's low lane takes x's value, and XMM2's and the memory
         * operand's take y's, XMM2's three entries later in the table, so
         * that the cases take every pair.
         */
        int i = rcg_value_index(x), j = rcg_value_index(y);

        for (int n = 0; n < 4; n++) {
            rcg_in.x[n][0] = rcg_fp_bits(c, (n & 1 ? i : j) + n / 2 * 3);
            rcg_in.x[n][1] = rcg_fp_bits(c, (n & 1 ? j : i) + 5);
        }
        rcg_in.mxcsr = s->mxcsr;
    }
    rcg_in.flags = s->flags;
    rcg_sub_in = s->sub_in;
    rcg_fill(RCG_MEM, RCG_MEM_SIZE, 0x5a);
    rcg_fill(RCG_STACK - RCG_STACK_SIZE, 2 * RCG_STACK_SIZE, 0xa5);

    if (c->mem && c->xmm >= RCG_XMM_F64) {
        rcg_store_fp(c, c->operand, y);
    } else if (c->mem) {
        rcg_store64(c->operand, y);
    }
    if (c->stack) {
        rcg_store64(c->rsp, y);
    }
    if (c->b >= 0) {
        rcg_in.r[c->b] = y;
    }
    if (c->a >= 0) {
        rcg_in.r[c->a] = x;
    }
    if (c->base >= 0) {
        rcg_in.r[c->base] = c->base_value;
    }
    if (c->index >= 0) {
        rcg_in.r[c->index] = c->index_value;
    }
}

/* FNV-1a, 64-bit. */
#define RCG_HASH_INIT 0xcbf29ce484222325ull

static inline uint64_t rcg_hash(uint64_t h, const void *p, size_t n)
{
    const uint8_t *b = p;

    for (size_t i = 0; i < n; i++) {
        h = (h ^ b[i]) * 0x100000001b3ull;
    }
    return h;
}

static inline void wrmsr(uint32_t msr, uint64_t v)
{
    asm volatile("wrmsr" : : "c"(msr), "a"((uint32_t)v),
                 "d"((uint32_t)(v >> 32)));
}

#define MSR_FS_BASE 0xc0000100
#define MSR_GS_BASE 0xc0000101

/*
 * Exceptions. Every vector below 32 goes, on a separate stack (IST1), to a
 * stub that pushes its number (and a zero where the CPU pushes no error
 * code), then to rcg_exception(), which each test defines to handle some
 * exceptions or none. One it does not handle stops the test with the
 * vector and RIP, rather than leaving it to triple-fault. With a separate
 * stack, the CPU's frame does not overwrite what is below the case's RSP.
 */
struct rcg_frame {
    uint64_t r[15];         /* RAX to R15, but RSP */
    uint64_t vector, error;
    uint64_t rip, cs, rflags, rsp, ss;
};

/* Returns true if the exception is handled and the instruction can resume. */
bool rcg_exception(struct rcg_frame *f);

void rcg_exception_entry(struct rcg_frame *f)
{
    if (!rcg_exception(f)) {
        ml_printf("FAIL: exception %ld (error %lx) at %lx\n", f->vector,
                  f->error, f->rip);
        asm volatile("outw %w0, $0xf4" : : "a"(1));
        for (;;) {
            asm volatile("hlt");
        }
    }
}

/* A stub, which pushes a zero unless v is a vector with an error code. */
#define RCG_STUB(v)                                                   \
    "rcg_vector_" #v ":\n"                                            \
    "    .if !(" #v " == 8 || (" #v " >= 10 && " #v " <= 14) || "     \
    #v " == 17 || " #v " == 21 || " #v " == 29 || " #v " == 30)\n"    \
    "    pushq $0\n"                                                  \
    "    .endif\n"                                                    \
    "    pushq $" #v "\n"                                             \
    "    jmp rcg_vector_common\n"

asm("    .pushsection .text\n"
    RCG_STUB(0) RCG_STUB(1) RCG_STUB(2) RCG_STUB(3) RCG_STUB(4)
    RCG_STUB(5) RCG_STUB(6) RCG_STUB(7) RCG_STUB(8) RCG_STUB(9)
    RCG_STUB(10) RCG_STUB(11) RCG_STUB(12) RCG_STUB(13) RCG_STUB(14)
    RCG_STUB(15) RCG_STUB(16) RCG_STUB(17) RCG_STUB(18) RCG_STUB(19)
    RCG_STUB(20) RCG_STUB(21) RCG_STUB(22) RCG_STUB(23) RCG_STUB(24)
    RCG_STUB(25) RCG_STUB(26) RCG_STUB(27) RCG_STUB(28) RCG_STUB(29)
    RCG_STUB(30) RCG_STUB(31)
    "rcg_vector_common:\n"
    "    push %r15\n    push %r14\n    push %r13\n    push %r12\n"
    "    push %r11\n    push %r10\n    push %r9\n    push %r8\n"
    "    push %rdi\n    push %rsi\n    push %rbp\n    push %rbx\n"
    "    push %rdx\n    push %rcx\n    push %rax\n"
    "    mov %rsp, %rdi\n"
    /*
     * Call with RSP 16-byte aligned, as the ABI wants. It already is, as the
     * stack's top is aligned and 22 quadwords follow, but this does not
     * depend on that.
     */
    "    mov %rsp, %rbx\n"
    "    and $-16, %rsp\n"
    "    call rcg_exception_entry\n"
    "    mov %rbx, %rsp\n"
    "    pop %rax\n    pop %rcx\n    pop %rdx\n    pop %rbx\n"
    "    pop %rbp\n    pop %rsi\n    pop %rdi\n    pop %r8\n"
    "    pop %r9\n    pop %r10\n    pop %r11\n    pop %r12\n"
    "    pop %r13\n    pop %r14\n    pop %r15\n"
    "    add $16, %rsp\n"
    "    iretq\n"
    "    .popsection\n"
    "    .pushsection .data\n"
    "    .balign 8\n"
    "rcg_vectors:\n"
    "    .quad rcg_vector_0, rcg_vector_1, rcg_vector_2, rcg_vector_3\n"
    "    .quad rcg_vector_4, rcg_vector_5, rcg_vector_6, rcg_vector_7\n"
    "    .quad rcg_vector_8, rcg_vector_9, rcg_vector_10, rcg_vector_11\n"
    "    .quad rcg_vector_12, rcg_vector_13, rcg_vector_14, rcg_vector_15\n"
    "    .quad rcg_vector_16, rcg_vector_17, rcg_vector_18, rcg_vector_19\n"
    "    .quad rcg_vector_20, rcg_vector_21, rcg_vector_22, rcg_vector_23\n"
    "    .quad rcg_vector_24, rcg_vector_25, rcg_vector_26, rcg_vector_27\n"
    "    .quad rcg_vector_28, rcg_vector_29, rcg_vector_30, rcg_vector_31\n"
    "    .popsection\n");

extern const uint64_t rcg_vectors[32];

static uint64_t rcg_idt[32 * 2] __attribute__((aligned(16)));

/* A 64-bit TSS, for its IST1: the stack the exception stubs run on. */
static struct {
    uint32_t reserved0;
    uint64_t rsp[3];
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap;
} __attribute__((packed, aligned(16))) rcg_tss;

static uint8_t rcg_ist_stack[16384] __attribute__((aligned(16)));

/* boot.S's GDT, copied, and the TSS's descriptor after it. */
static uint64_t rcg_gdt[16] __attribute__((aligned(16)));

/* The page directory that maps RCG_HI to RCG_MEM, with one 2 MiB page. */
static uint64_t rcg_hi_pd[512] __attribute__((aligned(4096)));

_Static_assert((RCG_MEM & 0x1fffff) == 0, "RCG_MEM is not 2 MiB aligned");

/* The end of the test binary, from kernel.ld. */
extern char __bss_en[];

struct rcg_table_reg {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

/* Loads a GDT that adds a TSS to boot.S's, with IST1 at rcg_ist_stack. */
static inline void rcg_init_tss(void)
{
    struct rcg_table_reg gdtr;
    uint64_t base = (uint64_t)&rcg_tss, limit = sizeof(rcg_tss) - 1;
    int n;

    asm volatile("sgdt %0" : "=m"(gdtr));
    n = (gdtr.limit + 1) / 8;
    for (int i = 0; i < n; i++) {
        rcg_gdt[i] = ((uint64_t *)gdtr.base)[i];
    }
    rcg_tss.ist[0] = (uint64_t)rcg_ist_stack + sizeof(rcg_ist_stack);
    rcg_tss.iomap = sizeof(rcg_tss);
    /* An available 64-bit TSS, present, in two descriptor slots. */
    rcg_gdt[n] = (limit & 0xffff) | (base & 0xffffff) << 16 | 0x89ull << 40 |
                 (limit >> 16 & 0xf) << 48 | (base >> 24 & 0xff) << 56;
    rcg_gdt[n + 1] = base >> 32;
    gdtr.limit = (n + 2) * 8 - 1;
    gdtr.base = (uint64_t)rcg_gdt;
    asm volatile("lgdt %0" : : "m"(gdtr));
    asm volatile("ltr %w0" : : "r"(n * 8));
}

/*
 * Maps RCG_HI to RCG_MEM through boot.S's page tables, whose PDP maps the
 * first 4 GiB and has the entry for the fifth free.
 */
static inline void rcg_init_hi(void)
{
    uint64_t cr3, *pml4, *pdp;

    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    pml4 = (uint64_t *)(cr3 & ~0xfffull);
    pdp = (uint64_t *)(pml4[(RCG_HI >> 39) & 511] & ~0xfffull);
    /* Present, writable, 2 MiB. */
    rcg_hi_pd[0] = RCG_MEM | 0x83;
    pdp[(RCG_HI >> 30) & 511] = (uint64_t)rcg_hi_pd | 0x3;
    asm volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
}

/*
 * Points the first 32 vectors at the stubs, on IST1, maps RCG_HI, sets FS's
 * and GS's bases, and turns SSE on. Stops the test if the binary reaches
 * the cases' data.
 */
static inline void rcg_init(void)
{
    uint64_t cr;
    uint16_t cs;
    struct rcg_table_reg idtr = { sizeof(rcg_idt) - 1, (uint64_t)rcg_idt };

    if ((uint64_t)__bss_en > RCG_MEM) {
        ml_printf("FAIL: the test binary ends at %lx, past RCG_MEM\n",
                  (uint64_t)__bss_en);
        asm volatile("outw %w0, $0xf4" : : "a"(1));
    }

    rcg_init_tss();
    asm volatile("mov %%cs, %0" : "=r"(cs));
    for (int v = 0; v < 32; v++) {
        uint64_t h = rcg_vectors[v];

        /* A present, ring-0 interrupt gate, on IST1. */
        rcg_idt[v * 2] = (h & 0xffff) | (uint64_t)cs << 16 |
                         0x8e01ull << 32 | (h >> 16 & 0xffff) << 48;
        rcg_idt[v * 2 + 1] = h >> 32;
    }
    asm volatile("lidt %0" : : "m"(idtr));
    rcg_init_hi();

    wrmsr(MSR_FS_BASE, RCG_FS_BASE);
    wrmsr(MSR_GS_BASE, RCG_GS_BASE);

    /* CR0.MP set and EM clear, CR4.OSFXSR and OSXMMEXCPT set. */
    asm volatile("mov %%cr0, %0" : "=r"(cr));
    asm volatile("mov %0, %%cr0" : : "r"((cr & ~4ull) | 2));
    asm volatile("mov %%cr4, %0" : "=r"(cr));
    asm volatile("mov %0, %%cr4" : : "r"(cr | 0x600));
}

#endif /* RCG_TEST_H */
