/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Page faults in the middle of every memory form RCG has a gadget for.
 *
 * Each case (from target/i386/tcg/rcg-gen.py; see rcg-test.h) accesses
 * memory from RBX, or the stack from RSP, which the test moves across a
 * page boundary byte by byte: from wholly below it, across it at every
 * split, to wholly above. The page above is first made not present, then
 * read-only. The page fault handler notes the fault and maps the page, and
 * the instruction runs again. Each such run must end exactly as a run with
 * the page mapped all along does, so nothing is done twice. At the fault
 * the instruction must not have started: RIP points at it, and the
 * registers, the flags and the memory around the boundary are as they
 * were before it. The fault's frame goes on a separate stack, so none of
 * that memory is lost to it. A branch goes to the end of the instruction.
 *
 * Each case also runs misaligned on the lower page, across a 16-byte
 * boundary, where it must not fault. Every run starts from the flags POPF
 * loads, again from the state a CMP leaves, and again from the state an
 * ADC leaves, which also uses cc_src2. From the last two, a write to the
 * lazy-flags state before the fault would show in the flags at the fault.
 */

#include "rcg-test.h"
#include "rcg-faults.h"

#define NB_CASES (sizeof(rcg_fault_cases) / sizeof(rcg_fault_cases[0]))

#define PAGE 4096

/* 2 MiB mapped with 4K pages, and the boundary in it between two pages. */
#define REGION 0x2000000ul
#define BOUNDARY (REGION + 2 * PAGE)

/* Page table entry bits: present, writable, accessed, dirty. */
#define PTE_P 0x1
#define PTE_W 0x2
#define PTE_A 0x20
#define PTE_D 0x40

/* The flags each case starts from: some of the arithmetic ones set. */
#define FLAGS_IN (0x2 | 0xc5)

/*
 * The starts: the flags from POPF, then a CMP of 0 with 1 (a borrow), then
 * an ADC of 1 to 0xf with CF set. That ADC sets AF, which TCG works out
 * from cc_src2, the carry in: had cc_src2 been written before the fault,
 * AF at the fault would be clear.
 */
static const struct rcg_start starts[] = {
    { FLAGS_IN, false, 0 },
    { FLAGS_IN, true, 0 },
    { FLAGS_IN, false, 0xf, true },
};
#define NB_STARTS (sizeof(starts) / sizeof(starts[0]))

/* How many bytes on each side of the boundary each run fills and compares. */
#define WINDOW 32
#define WINDOW_START (BOUNDARY - WINDOW)

/* What each run fills the window with. */
#define WINDOW_SEED 0x3c

/*
 * The values a case's registers a and b, and its memory operand, take. Each
 * ALU result of the two differs from the cc_dst the starts' CMP leaves, so
 * that an early write to cc_dst shows in the flags at the fault.
 */
#define VALUE_A 0x0123456789abcdefull
#define VALUE_B 0x1122334455667788ull

static uint64_t region_pt[512] __attribute__((aligned(PAGE)));

/* The upper page's entry, which the fault handler maps fully. */
#define UPPER_PTE region_pt[(BOUNDARY - REGION) / PAGE]

/* What the handler finds at a fault, for check_fault() to check. */
static int faults;
static uint64_t fault_rip, fault_rflags, fault_rsp, fault_cr2;
static uint64_t fault_r[15];
static uint64_t fault_x[4][2];
static uint64_t fault_vector;
static uint8_t fault_window[2 * WINDOW];

/* Where to go on after a #GP that the case should raise; 0 if it should not. */
static uint64_t gp_resume;

/* The window as the run started, for check_fault() to compare with. */
static uint8_t start_window[2 * WINDOW];

static uint64_t read_cr(int n)
{
    uint64_t v = 0;

    switch (n) {
    case 0:
        asm volatile("mov %%cr0, %0" : "=r"(v));
        break;
    case 2:
        asm volatile("mov %%cr2, %0" : "=r"(v));
        break;
    case 3:
        asm volatile("mov %%cr3, %0" : "=r"(v));
        break;
    }
    return v;
}

static void invlpg(uint64_t addr)
{
    asm volatile("invlpg (%0)" : : "r"(addr) : "memory");
}

bool rcg_exception(struct rcg_frame *f)
{
    if (f->vector != 14 && !(f->vector == 13 && gp_resume)) {
        return false;
    }
    faults++;
    fault_vector = f->vector;
    asm volatile("movups %%xmm0, %0\n\tmovups %%xmm1, %1\n\t"
                 "movups %%xmm2, %2\n\tmovups %%xmm3, %3"
                 : "=m"(fault_x[0]), "=m"(fault_x[1]), "=m"(fault_x[2]),
                   "=m"(fault_x[3]));
    fault_rip = f->rip;
    fault_rflags = f->rflags;
    fault_rsp = f->rsp;
    fault_cr2 = read_cr(2);
    for (int i = 0; i < 15; i++) {
        fault_r[i] = f->r[i];
    }
    if (f->vector == 13) {
        f->rip = gp_resume;
    } else {
        UPPER_PTE |= PTE_P | PTE_W;
        invlpg(BOUNDARY);
    }
    for (int i = 0; i < 2 * WINDOW; i++) {
        fault_window[i] = rcg_bytes(WINDOW_START)[i];
    }
    return true;
}

/* Maps REGION with 4K pages, through boot.S's page tables. */
static void map_region(void)
{
    uint64_t *pml4 = (uint64_t *)(read_cr(3) & ~0xfffull);
    uint64_t *pdp = (uint64_t *)(pml4[(REGION >> 39) & 511] & ~0xfffull);
    uint64_t *pd = (uint64_t *)(pdp[(REGION >> 30) & 511] & ~0xfffull);

    for (int i = 0; i < 512; i++) {
        region_pt[i] = (REGION + i * PAGE) | PTE_P | PTE_W | PTE_A | PTE_D;
    }
    pd[(REGION >> 21) & 511] = (uint64_t)region_pt | PTE_P | PTE_W | PTE_A;
    asm volatile("mov %0, %%cr3" : : "r"(read_cr(3)) : "memory");
}

/* The upper page's entry: mapped fully, not present, or read-only. */
enum upper { MAPPED, ABSENT, READ_ONLY };

static void set_upper(enum upper how)
{
    UPPER_PTE = BOUNDARY | PTE_A | PTE_D |
                (how == ABSENT ? 0 : PTE_P) | (how == MAPPED ? PTE_W : 0);
    invlpg(BOUNDARY);
}

/* The flags a CMP of v with 1 leaves, as the starts' CMP does. */
static uint64_t sub_flags(uint64_t v)
{
    uint64_t flags;

    asm volatile("cmpq $1, %1\n\tpushfq\n\tpopq %0"
                 : "=r"(flags) : "r"(v) : "cc");
    return flags;
}

/* The flags an ADC of 1 to v leaves with CF set, as the ADC start's does. */
static uint64_t adc_flags(uint64_t v)
{
    uint64_t flags;

    asm volatile("stc\n\tadcq $1, %1\n\tpushfq\n\tpopq %0"
                 : "=r"(flags), "+r"(v) : : "cc");
    return flags;
}

struct result {
    struct rcg_state out;
    uint8_t window[2 * WINDOW];
};

/*
 * Runs case c from start s with its access at addr and the upper page set
 * to how, into r. For a case that moves RSP, RSP is placed so that its
 * stack access is at addr. A branch's target is the instruction's end.
 * Returns the starting RSP.
 */
static uint64_t run(const struct rcg_case *c, const struct rcg_start *s,
                    uint64_t addr, enum upper how, struct result *r)
{
    uint64_t rsp, end = rcg_insn_end(c, s);

    rcg_setup(c, VALUE_A, VALUE_B, s);
    if (c->moved == R_ESP) {
        /* PUSH writes the 8 bytes below RSP; POP reads the 8 above. */
        rcg_in.r[R_ESP] = c->writes ? addr + 8 : addr;
    } else {
        rcg_in.r[c->moved] = addr;
    }
    rsp = rcg_in.r[R_ESP];
    rcg_fill(WINDOW_START, 2 * WINDOW, WINDOW_SEED);
    if (c->target == RCG_TARGET_MEM) {
        rcg_store64(c->moved == R_ESP ? c->operand : addr, end);
    } else if (c->target == RCG_TARGET_STACK) {
        rcg_store64(rsp, end);
    } else if (c->target >= 0) {
        rcg_in.r[c->target] = end;
    }
    for (int i = 0; i < 2 * WINDOW; i++) {
        start_window[i] = rcg_bytes(WINDOW_START)[i];
    }

    set_upper(how);
    /*
     * INVLPG may flush the whole TLB. Put the lower page back in it, so that
     * an access within that page takes the gadget's fast path.
     */
    (void)*(volatile uint8_t *)WINDOW_START;
    faults = 0;
    rcg_run(c, s);
    set_upper(MAPPED);
    r->out = rcg_out;
    r->out.flags &= RCG_FLAGS;
    for (int i = 0; i < 2 * WINDOW; i++) {
        r->window[i] = rcg_bytes(WINDOW_START)[i];
    }
    return rsp;
}

static int checks, failed, taken;

static void check(bool ok, const struct rcg_case *c, const struct rcg_start *s,
                  int below, enum upper how, const char *what)
{
    checks++;
    if (!ok) {
        failed++;
        ml_printf("FAIL: %s%s, %d bytes below the boundary, upper page %s: "
                  "%s\n", c->name,
                  s->adc ? " after an ADC" : s->sub ? " after a CMP" : "",
                  below,
                  how == MAPPED ? "mapped" :
                  how == ABSENT ? "absent" : "read-only", what);
    }
}

/* Checks what the handler found at a fault against how the run started. */
static void check_fault(const struct rcg_case *c, const struct rcg_start *s,
                        int below, enum upper how, uint64_t rsp)
{
    uint64_t flags_in = s->adc ? adc_flags(s->sub_in) :
                        s->sub ? sub_flags(s->sub_in) : FLAGS_IN;
    bool same = true;

    check(fault_rip == rcg_insn_addr(c, s), c, s, below, how,
          "RIP at the fault is not the instruction's");
    check((fault_rflags & RCG_FLAGS) == (flags_in & RCG_FLAGS), c, s, below,
          how, "flags changed before the fault");
    check(fault_rsp == rsp, c, s, below, how, "RSP changed before the fault");

    /* The frame has RAX to R15 without RSP. */
    for (int i = 0; i < 15; i++) {
        same &= fault_r[i] == rcg_in.r[i < R_ESP ? i : i + 1];
    }
    check(same, c, s, below, how, "registers changed before the fault");
    same = true;
    for (int b = 0; b < 2 * WINDOW; b++) {
        same &= fault_window[b] == start_window[b];
    }
    check(same, c, s, below, how, "memory changed before the fault");
    if (c->xmm) {
        same = true;
        for (int i = 0; i < 4; i++) {
            same &= fault_x[i][0] == rcg_in.x[i][0] &&
                    fault_x[i][1] == rcg_in.x[i][1];
        }
        check(same, c, s, below, how, "XMM changed before the fault");
    }
}

/*
 * A case with XMM registers loads XMM1 or stores XMM2, at addr. A run across
 * the boundary goes through the helper, which rcg-insns' cases need not
 * reach, so compare the result with memory, rather than with TCG's. A
 * narrower load clears the rest of XMM1, and a narrower store leaves the
 * memory after it alone.
 */
static void check_xmm_access(const struct rcg_case *c,
                             const struct rcg_start *s, int below,
                             uint64_t addr, const struct result *r)
{
    int off = addr - WINDOW_START;
    const uint8_t *mem = (c->writes ? r->window : start_window) + off;
    const uint8_t *reg = c->writes ? (const uint8_t *)rcg_in.x[2]
                                   : (const uint8_t *)r->out.x[1];
    bool same = true;

    for (int i = 0; i < c->width / 8; i++) {
        same &= mem[i] == reg[i];
    }
    check(same, c, s, below, MAPPED, "XMM and memory differ");
    same = true;
    for (int i = c->width / 8; i < 16; i++) {
        same &= c->writes ? mem[i] == start_window[off + i] : reg[i] == 0;
    }
    check(same, c, s, below, MAPPED,
          c->writes ? "wrote beyond the lane" : "did not clear above the lane");
}

/*
 * Runs case c from the start s with below bytes of its access below the
 * boundary, mapped and then with the upper page absent and read-only.
 */
static void run_at(const struct rcg_case *c, const struct rcg_start *s,
                   int size, int below)
{
    uint64_t addr = BOUNDARY - below;
    bool touches_upper = below < size;
    struct result want, got;

    run(c, s, addr, MAPPED, &want);
    check(faults == 0, c, s, below, MAPPED, "faulted");
    if (c->xmm) {
        check_xmm_access(c, s, below, addr, &want);
    }

    for (enum upper how = ABSENT; how <= READ_ONLY; how++) {
        bool expect = touches_upper && (how == ABSENT || c->writes);
        uint64_t rsp = run(c, s, addr, how, &got);
        bool same = true;

        check(faults == expect, c, s, below, how,
              expect ? "did not fault once" : "faulted");
        taken += faults;
        if (faults == 1 && expect) {
            check((fault_cr2 & ~(PAGE - 1ull)) == BOUNDARY, c, s, below, how,
                  "CR2 is not in the upper page");
            check_fault(c, s, below, how, rsp);
        }

        for (int r = 0; r < 16; r++) {
            same &= got.out.r[r] == want.out.r[r];
        }
        check(same && got.out.flags == want.out.flags, c, s, below, how,
              "registers or flags differ after the retry");
        same = true;
        for (int i = 0; i < 16; i++) {
            same &= got.out.cc[i] == want.out.cc[i];
        }
        check(same, c, s, below, how, "SETcc differs after the retry");
        if (c->xmm) {
            same = true;
            for (int i = 0; i < 4; i++) {
                same &= got.out.x[i][0] == want.out.x[i][0] &&
                        got.out.x[i][1] == want.out.x[i][1];
            }
            check(same, c, s, below, how, "XMM differs after the retry");
        }
        same = true;
        for (int b = 0; b < 2 * WINDOW; b++) {
            same &= got.window[b] == want.window[b];
        }
        check(same, c, s, below, how, "memory differs after the retry");
    }
}

/*
 * A move that must be aligned: on a 16-byte boundary it faults in the upper
 * page or not at all. Off one it raises #GP, with nothing written, both
 * across the boundary, where the helper checks it, and within the lower page,
 * where the gadget must.
 */
static void run_aligned(const struct rcg_case *c, const struct rcg_start *s)
{
    run_at(c, s, 16, 0);
    run_at(c, s, 16, 16);

    for (int below = 8; below <= 24; below += 16) {
        struct result r;
        uint64_t rsp;

        gp_resume = rcg_insn_end(c, s);
        rsp = run(c, s, BOUNDARY - below, MAPPED, &r);
        gp_resume = 0;
        check(faults == 1 && fault_vector == 13, c, s, below, MAPPED,
              "did not raise #GP once");
        taken += faults;
        if (faults == 1) {
            check_fault(c, s, below, MAPPED, rsp);
        }
    }
}

int main(void)
{
    uint64_t cr0 = read_cr(0);

    /* Make ring 0's writes to read-only pages fault too. */
    asm volatile("mov %0, %%cr0" : : "r"(cr0 | (1 << 16)));
    rcg_init();
    map_region();

    for (int i = 0; i < NB_CASES; i++) {
        const struct rcg_case *c = &rcg_fault_cases[i];
        int size = c->moved == R_ESP ? 8 : c->width / 8;

        for (int s = 0; s < NB_STARTS; s++) {
            if (c->aligned) {
                run_aligned(c, &starts[s]);
                continue;
            }
            /* below is how many of the access's bytes are under BOUNDARY. */
            for (int below = 0; below <= size; below++) {
                run_at(c, &starts[s], size, below);
            }
            /* On the lower page, across the 16-byte boundary below it. */
            if (size > 1) {
                run_at(c, &starts[s], size, 16 + size / 2);
            }
        }
    }

    ml_printf("%d checks, %d failed, %d faults taken\n", checks, failed,
              taken);
    return failed ? 1 : 0;
}
