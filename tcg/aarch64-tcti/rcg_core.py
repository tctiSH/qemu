# SPDX-License-Identifier: GPL-2.0-or-later
""" What RCG's gadget generators have in common, whatever the guest.

A guest's generator, target/<arch>/tcg/rcg-gen.py, holds that guest's
tables, the bodies of its gadgets and its tests' cases. This holds the
host's side that none of those change: the registers a body computes in
and how it reaches guest memory through TCTI's templates (Body), the ways
a gadget can be entered and left (Harness, with TCTI's and the checker's),
and the frames of what a generator writes: the gadgets' source files, the
head of the translator's table, the tests' cases and the coverage check.

A generator imports this as it imports tcti_memory, from this directory.
"""

import os
import re
import sys

import tcti_memory


#
# The stream: how a gadget's operand words are packed.
#

def stream_words(words, narrow_words):
    """ How a spec's words go in the stream, which the translator's
    rcg_pack_words() must match: a list of stream words, each a tuple of
    the words it holds. narrow_words are the guest's words that always fit
    in 32 bits, signed. A gadget that accesses memory, which is one with a
    tlb word, has its narrow words two to a stream word, the first in the
    low half, then an odd one out alone, then each of the others alone. Any
    other gadget has each word alone. A memory gadget splits the pairs
    while it waits for the TLB entry; packing the others only made them
    slower. """
    if "tlb" not in words:
        return [(w,) for w in words]
    narrow = [w for w in words if w in narrow_words]
    return ([tuple(narrow[i:i + 2]) for i in range(0, len(narrow), 2)] +
            [(w,) for w in words if w not in narrow_words])


#
# The host's side: what a gadget body is written with.
#

# A gadget's operand words arrive in these registers, in order, however the
# spec's stream holds them. They are none of x0-x4, which a slow path sets
# up as a helper's arguments before it is done with the words; a slow path
# that sets x5 or x6 too does so last.
WORD_REGS = ("x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12")

# What a body computes in: the address, the first and second operands, the
# result, and scratch.
ADDR, A, B, R, T = "x0", "x1", "x2", "x3", "x4"

# The memory templates' output: the TLB addend after a fast path, and the
# value after a load's slow path.
OUT = tcti_memory.TMP[1]

# Loads by width: the plain access, from [addr, addend]; the ordered one
# (LDAPR), from the host address, which the template leaves in OUT; and the
# cputlb helper for the slow path. Both accesses zero-extend. STORES is
# the same for stores, with STLR.
LOADS = {
    8:  ("ldrb {w}, [{addr}, {out}]", "ldaprb {w}, [{out}]", "helper_ldub_mmu"),
    16: ("ldrh {w}, [{addr}, {out}]", "ldaprh {w}, [{out}]", "helper_lduw_mmu"),
    32: ("ldr {w}, [{addr}, {out}]",  "ldapr {w}, [{out}]",  "helper_ldul_mmu"),
    64: ("ldr {x}, [{addr}, {out}]",  "ldapr {x}, [{out}]",  "helper_ldq_mmu"),
}
STORES = {
    8:  ("strb {w}, [{addr}, {out}]", "stlrb {w}, [{out}]", "helper_stb_mmu"),
    16: ("strh {w}, [{addr}, {out}]", "stlrh {w}, [{out}]", "helper_stw_mmu"),
    32: ("str {w}, [{addr}, {out}]",  "stlr {w}, [{out}]",  "helper_stl_mmu"),
    64: ("str {x}, [{addr}, {out}]",  "stlr {x}, [{out}]",  "helper_stq_mmu"),
}


def w(reg):
    """ The 32-bit view of an x register. """
    return "w" + reg[1:]


ARM_INVERT = {"eq": "ne", "ne": "eq", "cs": "cc", "cc": "cs", "lo": "hs",
              "hs": "lo", "mi": "pl", "pl": "mi", "vs": "vc", "vc": "vs",
              "hi": "ls", "ls": "hi", "ge": "lt", "lt": "ge", "gt": "le",
              "le": "gt"}


class Harness:
    """ How a gadget is entered, how it gets its operand words and how it
    leaves: the part of a gadget that differs between the ways RCG's gadgets
    can run. Each way subclasses this.

    env is the register that holds env. A gadget's body may use the
    registers of scratch, and keeps every other register. It passes retaddr
    to a cputlb helper as the return address the helper unwinds from, and
    keeps what it needs across that call with save and restore. getpc holds
    the address of tcti_call_return_address, from which a helper that may
    raise reads GETPC(): TCTI's call gadget stores retaddr there before
    each call. """

    env = "x14"
    retaddr = "x28"
    getpc = "x25"
    save = tcti_memory.C_CALL_PROLOGUE
    restore = tcti_memory.C_CALL_EPILOGUE
    scratch = (*(f"x{n}" for n in range(14)), *tcti_memory.TMP)

    def enter(self, stream):
        """ The lines that load the gadget's operand words into their
        registers: stream holds, for each of the spec's stream words, the
        registers of its words. """
        raise NotImplementedError

    def leave(self):
        """ The lines that end the gadget, going on to what follows it. """
        raise NotImplementedError

    def load_table(self, qreg):
        """ The lines that load a spec's table (its has_table), after its
        words in the stream, into qreg. """
        raise NotImplementedError

    def branch(self, arm, labels):
        """ The lines that make the gadget go on at its target instead, if
        the host's condition arm holds. labels are numeric labels reserved
        for these lines, so they cannot clash with those of a load in the
        same body. """
        raise NotImplementedError

    def jumps(self, arm, labels):
        """ The lines on the way through and the slow-path lines of a branch
        if arm holds that also makes the jump to the next TB each way (see
        tcg_gen_rich_br()), as x86's jccgoto and fjccgoto do, with labels as
        for branch(). """
        raise NotImplementedError

    def assemble(self, stream, hot, cold, table):
        """ The whole gadget, from the stream words' registers, the body's
        lines on the way through and its slow paths. table is the slice of
        hot that loads the spec's table, or None if it has none. """
        return [*self.enter(stream), *hot, *self.leave(), *cold]


class Body:
    """ A gadget body as it is written: the lines on the way through (hot),
    and the slow paths, which go after the gadget's end and branch back
    (cold). This is the part no guest changes: the words, the labels, what
    a slow path keeps across its call, and guest memory. A generator
    subclasses it with its guest's registers and flags.

    spec is the gadget's spec, of which a body needs name, words (the
    operand words, in the translator's order), stream (how they go in the
    stream; see stream_words()) and ordered (whether it is the twin that
    keeps the guest's memory order). """

    def __init__(self, spec, harness):
        self.spec = spec
        self.h = harness
        self.env = harness.env
        assert len(spec.words) <= len(WORD_REGS), spec.name
        self.word_regs = dict(zip(spec.words, WORD_REGS))
        self.hot = []
        self.cold = []
        self.label = 0
        self.used = set()
        self.table = None

    def word(self, name):
        return self.word_regs[name]

    def load_table(self, qreg):
        """ qreg = the spec's table (its has_table), after any access to
        guest memory. """
        lines = self.h.load_table(qreg)
        self.table = slice(len(self.hot), len(self.hot) + len(lines))
        self.emit(*lines)

    def emit(self, *lines):
        self.hot.extend(lines)

    def define(self, *regs):
        """ Notes that regs hold values from here on, for the slow paths
        that follow to keep. """
        self.used.update(regs)

    def lines(self):
        """ The whole gadget. """
        layout = self.spec.stream
        assert sorted(sum(layout, ())) == sorted(self.spec.words), \
            self.spec.name
        stream = [tuple(map(self.word, words)) for words in layout]
        return self.h.assemble(stream, self.hot, self.cold, self.table)

    def _labels(self):
        self.label += 2
        return str(self.label - 1), str(self.label)

    def _save(self, keep):
        """ The harness's save and restore, also keeping the registers of
        keep across the call. """
        keep = sorted(set(keep), key=lambda r: int(r[1:]))
        if len(keep) % 2:
            keep.append("xzr")
        pairs = list(zip(keep[::2], keep[1::2]))
        save = [*self.h.save, *(f"stp {a}, {b}, [sp, #-16]!" for a, b in pairs)]
        restore = [*(f"ldp {a}, {b}, [sp], #16" for a, b in reversed(pairs)),
                   *self.h.restore]
        return save, restore

    def _save_live(self):
        """ _save() of the registers defined so far and the words. """
        return self._save(self.used | set(self.word_regs.values()))

    def _store_barrier(self):
        """ The ordered twin's DMB ISHST before a store, or nothing. """
        return ["dmb ishst"] if self.spec.ordered else []

    def _memop(self):
        """ The line that puts the MemOpIdx in a helper's argument. """
        return "mov   {}, " + self.word("oi")

    def load(self, dest, addr, width):
        """ dest = the width bits of guest memory at addr, zero-extended. """
        ordered = self.spec.ordered
        plain, ldapr, helper = LOADS[width]
        access = (ldapr if ordered else plain).format(w=w(dest), x=dest,
                                                      addr=addr, out=OUT)
        miss, join = self._labels()
        size = width // 8
        self.emit(*tcti_memory.load_fast_path(
            [access], addr=addr, ordered=size if ordered else None,
            miss_label=miss, env=self.env, tlb=self.word("tlb"),
            cmp_operand="tlb_cmp_read", size=size))
        self.emit(f"{join}:")
        save, restore = self._save_live()
        self.cold += [
            *tcti_memory.load_slow_path(
                helper, self._memop(), addr=addr,
                ordered=size if ordered else None, miss_label=miss,
                env=self.env, retaddr=self.h.retaddr, save=save,
                restore=restore),
            f"mov {dest}, {OUT}",
            f"b {join}b",
        ]
        self.define(dest)

    def store(self, value, addr, width):
        """ The width bits of value to guest memory at addr. """
        ordered = self.spec.ordered
        plain, stlr, helper = STORES[width]
        access = (stlr if ordered else plain).format(w=w(value), x=value,
                                                     addr=addr, out=OUT)
        miss, join = self._labels()
        size = width // 8
        self.emit(*tcti_memory.store_fast_path(
            [access], addr=addr, ordered=size if ordered else None,
            miss_label=miss, env=self.env, tlb=self.word("tlb"),
            cmp_operand="tlb_cmp_write", size=size))
        self.emit(f"{join}:")
        save, restore = self._save_live()
        self.cold += [
            *tcti_memory.store_slow_path(
                helper, self._memop(), w(value) if width < 64 else value,
                addr=addr, ordered=size if ordered else None,
                miss_label=miss, env=self.env, retaddr=self.h.retaddr,
                save=save, restore=restore),
            f"b {join}b",
        ]

    def _pair_fast_path(self, insn, a, b, addr, size, aligned):
        """ The fast path of a 16- or 32-byte access (size) to guest memory
        at addr: one TLB lookup for all of it, then insn, LDP or STP, of a
        and b. aligned says the access must be on a size-byte boundary: one
        that is not goes to the slow path. The ordered twin puts DMB ISHLD
        after a load, past join, so that it covers the slow path too, and
        DMB ISHST before a store, which a store's slow path must repeat
        before its helper call. Returns miss and join: the caller writes
        the slow path, from miss, and branches back to join. """
        assert insn in ("ldp", "stp")
        out = OUT
        miss, join = self._labels()
        write = insn == "stp"
        if aligned:
            self.emit(f"tst {addr}, #{size - 1}", f"b.ne {miss}f")
        self.emit(*tcti_memory.create_tlb_fastpath(
            is_write=write, size=size, addr=addr, miss_label=miss,
            env=self.env, tlb=self.word("tlb"),
            cmp_operand="tlb_cmp_write" if write else "tlb_cmp_read"),
                  f"add {out}, {out}, {addr}",
                  *(self._store_barrier() if write else []),
                  f"{insn} {a}, {b}, [{out}]",
                  f"{join}:")
        if not write and self.spec.ordered:
            self.emit("dmb ishld")
        return miss, join

    def _call(self, helper, args, called=(), after=()):
        """ The lines of a slow path's call of helper, between the
        harness's save and restore (see _save_live()). x0 is env; args are
        the lines that set the other arguments, and anything else that must
        come right before the call. called are the lines right after the
        call, and after the lines after the restore. """
        save, restore = self._save_live()
        return [*save, f"mov x0, {self.env}", *args, f"bl _{helper}",
                *called, *restore, *after]

    def load128(self, lo, hi, addr, aligned):
        """ lo and hi = the 16 bytes of guest memory at addr, with one
        LDP, as in TCTI's qemu_ld_i128 gadgets. The translator requires
        LSE2, which makes an aligned LDP single-copy atomic. aligned
        says the access must be on a 16-byte boundary: one that is not goes
        to the helper, which raises the fault. The ordered twin orders it
        before what follows with DMB ISHLD, as those gadgets do. """
        t, out, page = tcti_memory.TMP
        miss, join = self._pair_fast_path("ldp", lo, hi, addr, 16, aligned)
        self.cold += [
            f"{miss}:",
            f"mov {out}, {addr}",
            *self._call("helper_ld16_mmu",
                        [f"mov x1, {out}", self._memop().format("x2"),
                         f"mov x3, {self.h.retaddr}"],
                        # Int128 comes back in x0 and x1, which the restore
                        # may reload.
                        called=[f"mov {t}, x0", f"mov {page}, x1"],
                        after=[f"mov {lo}, {t}", f"mov {hi}, {page}"]),
            f"b {join}b",
        ]
        self.define(lo, hi)

    def store128(self, lo, hi, addr, aligned):
        """ The 16 bytes of lo and hi to guest memory at addr, the reverse
        of load128(), with one STP; the ordered twin puts DMB ISHST before
        it. """
        t, out, page = tcti_memory.TMP
        miss, join = self._pair_fast_path("stp", lo, hi, addr, 16, aligned)
        self.cold += [
            f"{miss}:",
            # Out of the way of the helper's arguments.
            f"mov {t}, {addr}",
            f"mov {out}, {lo}",
            f"mov {page}, {hi}",
            *self._call("helper_st16_mmu",
                        [f"mov x1, {t}", f"mov x2, {out}", f"mov x3, {page}",
                         self._memop().format("x4"),
                         f"mov x5, {self.h.retaddr}",
                         *self._store_barrier()]),
            f"b {join}b",
        ]

    def branch(self, arm):
        """ The harness's branch to the gadget's target if arm holds. """
        self.emit(*self.h.branch(arm, self._labels()))

    def jumps(self, arm):
        """ The harness's branch if arm holds, then the jump each way. """
        hot, cold = self.h.jumps(arm, (*self._labels(), *self._labels()))
        self.emit(*hot)
        self.cold += cold


# The "i" asm operands the memory templates use, which the C compiler works
# out from QEMU's definitions. They are the TLB lookup's (see
# tcti_memory.tlb_operands()), with two changes: the CPUTLBDescFast's offset
# is a word instead, and the comparator is two operands, one to read and one
# to write, as a gadget may do both. HARNESS_OPERANDS is the exit request's
# offset, for TctiHarness.jumps(). A generator's own operands, those its
# bodies use directly, go with these.
MEMORY_OPERANDS = {
    "tlb_shift": "TCTI_TLB_INDEX_SHIFT",
    "tlb_cmp_read": "offsetof(CPUTLBEntry, addr_read)",
    "tlb_cmp_write": "offsetof(CPUTLBEntry, addr_write)",
    "tlb_addend": "offsetof(CPUTLBEntry, addend)",
    "tlb_page_mask": "TCTI_TLB_PAGE_MASK",
}
HARNESS_OPERANDS = {
    "exit_ofs": "TCTI_EXIT_REQUEST_OFS",
}


#
# Checking the bodies without building them.
#

class CheckHarness(Harness):
    """ A harness that only marks where a gadget is entered, branches and
    leaves, so that a generator can render every body without building it
    (see check_lines()). """

    def enter(self, stream):
        return [f"// enter: {', '.join(r for regs in stream for r in regs)}"]

    def leave(self):
        return ["// leave"]

    def load_table(self, qreg):
        return [f"// table: {qreg}"]

    def branch(self, arm, labels):
        return [f"// branch if {arm}"]

    def jumps(self, arm, labels):
        return [f"// jumps if {arm}"], []


def check_lines(name, lines, harness, operands):
    """ Checks the rendered lines of gadget name, from harness: that each
    names only the asm operands of operands and the registers a body may
    use, none of V8 to V15, which TCTI expects unchanged, and that every
    branch it makes has a label to go to. """
    h = harness
    allowed = {*h.scratch, h.env, h.retaddr, "x15", "sp", "lr", "xzr"}
    labels = {line[:-1] for line in lines if re.fullmatch(r"\d+:", line)}
    for line in lines:
        if line.startswith("//"):
            continue
        for operand in re.findall(r"%\[(\w+)\]", line):
            assert operand in operands, (name, line)
        # The getpc register may appear, but only as a base address.
        regs = line.replace(f"[{h.getpc}]", "")
        for reg in re.findall(r"\b([xw](?:\d+|zr)|sp|lr)\b", regs):
            assert "x" + reg[1:] in allowed or reg in allowed, (name, line)
        for reg in re.findall(r"(?<![.%])\b[vqdsh](\d+)\b", line):
            assert not 8 <= int(reg) <= 15, (name, line)
        for target in re.findall(r"(?<!\.)\b(\d+)[bf]\b", line):
            assert target in labels, (name, line)


#
# TCTI's gadgets, and the head of the translator's table of them.
#

# The most operand words a gadget takes.
MAX_WORDS = len(WORD_REGS)
# The stream words of a gadget's table (see Harness.load_table()): its 16
# bytes.
TABLE_WORDS = 2


class TctiHarness(Harness):
    """ TCTI's streams: tcg_out_rich() writes a gadget's address, then its
    operand words, in the spec's stream words. The gadget loads the words
    first, so x28, the return address its slow paths pass or store, points
    past them. """

    def enter(self, stream):
        # Each stream word loads into its last word's register. A pair is
        # then split: SXTW puts the low half in the first word's register,
        # and ASR #32 leaves the high half in the second's.
        regs = [words[-1] for words in stream]
        lines = [f"ldp {a}, {b}, [x28], #16"
                 for a, b in zip(regs[::2], regs[1::2])]
        if len(regs) % 2:
            lines.append(f"ldr {regs[-1]}, [x28], #8")
        for words in stream:
            if len(words) == 2:
                lo, hi = words
                lines += [f"sxtw {lo}, w{hi[1:]}", f"asr {hi}, {hi}, #32"]
        return lines

    def leave(self):
        return ["ldr x27, [x28], #8", "br x27"]

    def load_table(self, qreg):
        # Once the words are loaded, x28 points at the table, and this load
        # moves it past. A slow path taken before the load sees x28 still
        # inside this instruction's stream, as in any other gadget.
        return [f"ldr {qreg}, [x28], #{TABLE_WORDS * 8}"]

    def branch(self, arm, labels):
        # tcg_out_rich_br() writes the target after the words. Branching,
        # rather than a CSEL into x28, lets the gadgets that follow run
        # ahead on the predicted path instead of waiting for the condition.
        skip = labels[0]
        return ["ldr x27, [x28], #8", f"b.{ARM_INVERT[arm]} {skip}f",
                "mov x28, x27", f"{skip}:"]

    def jumps(self, arm, labels):
        # tcti_join_rich_br() swaps this gadget in for the jcc or fjcc gadget
        # when the code at the target and the code after the target word in
        # the stream both start with an addi_env_goto_tb gadget. This one skips
        # that gadget's address and does its work for the way it goes, and
        # each way leaves by a separate branch.
        taken, past, past_taken = labels[:3]
        hot = ["ldr x27, [x28], #8", f"b.{arm} {taken}f",
               "add x28, x28, #8", *self._goto_tb(past)]
        cold = [f"{taken}:", "add x28, x27, #8", *self._goto_tb(past_taken),
                *self.leave()]
        return hot, cold

    def _goto_tb(self, label):
        """ What tcti-gadget-gen.py's addi_env_goto_tb does after its
        address: add the immediate to the env slot, then go on at the target
        word unless an exit is requested, in which case at the exit_tb after
        it. """
        env = self.env
        return ["ldp x1, x2, [x28], #16",
                f"ldr x3, [{env}, x1]",
                "add x3, x3, x2",
                f"str x3, [{env}, x1]",
                f"ldr w4, [{env}, %[exit_ofs]]",
                "ldr x27, [x28], #8",
                f"tbnz w4, #31, {label}f",
                "mov x28, x27",
                f"{label}:"]

    def assemble(self, stream, hot, cold, table):
        # A body with no slow path that leaves x27 and x28 alone, a table
        # load aside, loads the next gadget's address before its body, as
        # tcti-gadget-gen.py's simple() does, so the dispatch target is
        # known sooner. The table load goes first, as the table comes before
        # that address in the stream.
        load = hot[table] if table else []
        rest = hot[:table.start] + hot[table.stop:] if table else hot
        if cold or any(re.search(r"\b[xw]2[78]\b", line) for line in rest):
            return super().assemble(stream, hot, cold, table)
        return [*self.enter(stream), *load, "ldr x27, [x28], #8", *rest,
                "br x27"]



def write_gadgets(outdir, files, includes, operands, gadgets):
    """ Writes TCTI's gadgets as naked functions to outdir, in a source file
    rcg_gadgets_<file>.c for each name in files, split so that they compile
    in parallel. includes are the headers the files need between osdep.h
    and tcti-gadget-defs.h, operands the "i" asm operands the bodies name,
    and gadgets gives each gadget's file, name and lines. Returns how many
    instructions the gadgets have. """
    operands = ", ".join(f'[{k}] "i" ({v})' for k, v in operands.items())
    out = {}
    for name in files:
        f = open(os.path.join(outdir, f"rcg_gadgets_{name}.c"), "w")
        print("/* Automatically generated by rcg-gen.py. Do not edit. */\n",
              file=f)
        print('#include "qemu/osdep.h"', file=f)
        for header in includes:
            print(f'#include "{header}"', file=f)
        print('#include "tcti-gadget-defs.h"\n', file=f)
        out[name] = f

    instructions = 0
    for file, name, lines in gadgets:
        f = out[file]
        instructions += sum(1 for line in lines
                            if not line.endswith(":") and
                            not line.startswith("."))
        print(f"void rcg_gadget_{name}(void);", file=f)
        print(f"__attribute__((naked)) void rcg_gadget_{name}(void)",
              file=f)
        print("{\n    asm(", file=f)
        for line in lines:
            print(f'        "{line}\\n"', file=f)
        print(f"        :: {operands});\n}}\n", file=f)
    for f in out.values():
        f.close()
    return instructions


def write_table_head(out, assumptions, word_names, narrow_words):
    """ The start of the translator's table: assumptions, what the bodies
    take for granted of QEMU's definitions beyond what their operands say,
    as QEMU_BUILD_BUG_ONs; the words a gadget can take, word_names, as
    RCG_W_*; and which of them stream_words() treats as narrow_words. """
    p = lambda *a: print(*a, file=out)
    p("/* Automatically generated by rcg-gen.py. Do not edit. */\n")
    p("/* What the bodies assume of QEMU's definitions. */")
    for assumption in assumptions:
        p(f"QEMU_BUILD_BUG_ON({assumption});")
    p("")
    p("enum {")
    p("    RCG_W_END,")
    for w in word_names:
        p(f"    RCG_W_{w.upper()},")
    p("};")
    p(f"#define RCG_MAX_WORDS {MAX_WORDS}")
    p(f"#define RCG_TABLE_WORDS {TABLE_WORDS}\n")
    p("/* Whether a word always fits in 32 bits, signed: rcg_pack_words(). */")
    p("static inline bool rcg_word_narrow(uint8_t w)\n{\n    switch (w) {")
    for w in narrow_words:
        p(f"    case RCG_W_{w.upper()}:")
    p("        return true;\n    default:\n        return false;\n    }\n}\n")


def write_gadget_type(out):
    """ The table's entry for one gadget: its address and its words. """
    p = lambda *a: print(*a, file=out)
    p("typedef struct RCGGadget {")
    p("    const void *gadget;")
    p("    uint8_t words[RCG_MAX_WORDS];")
    p("} RCGGadget;\n")


#
# The tests.
#

def write_cases(cases, out, prefix, define, row):
    """ The cases as the macros of the guest's rcg-test.h, which make the
    functions that run each case's instruction, then a table of the cases,
    of struct rcg_case. define gives the macro lines of a case and row the
    fields of its entry in the table, each from the case's name, prefix and
    its number, and the case. """
    cases = list(cases)
    print("/* Automatically generated by rcg-gen.py. Do not edit. */\n",
          file=out)
    for i, c in enumerate(cases):
        for line in define(f"{prefix}{i}", c):
            print(line, file=out)
    print(f"\nstatic const struct rcg_case {prefix}cases[] = {{", file=out)
    for i, c in enumerate(cases):
        print(f"    {{ {row(f'{prefix}{i}', c)} }},", file=out)
    print("};", file=out)


def check_coverage(order, nm, traces, specs, setters):
    """ Checks that the rcg_insn and rcg_jumps trace events in traces, from
    runs of a QEMU system emulator, took every gadget of specs that the
    translator or TCTI can pick under order: "ordered" where
    tcg_ldst_ordered() holds, which picks the ordered twins, else "plain".
    nm is nm's listing of that
    QEMU, from which each trace's ASLR slide is found. The events come at
    translation, so this says that each gadget was picked, not that it
    ran. Also checks that a branch right after a setter it can join took a
    fused gadget, which the tests' hashes cannot show: setters gives, for
    the name of each such setter, what the name of the branch gadget it
    should not be followed by starts with. Returns whether both hold. """

    names = {}
    for line in open(nm):
        parts = line.split()
        if len(parts) == 3 and parts[2].lstrip("_").startswith("rcg_gadget_"):
            names[int(parts[0], 16)] = parts[2].lstrip("_")[11:]
    taken = set()
    unjoined = set()
    for path in traces:
        picked = []
        for line in open(path):
            m = re.search(r"rcg_(?:insn pc 0x[0-9a-f]+|jumps) gadget "
                          r"(0x[0-9a-f]+)", line)
            if m:
                picked.append(int(m.group(1), 16))
        seen = set(picked)
        if not seen:
            continue
        # The one slide, a whole number of 16 KiB pages, that puts every
        # gadget taken on a gadget.
        first = min(seen)
        slides = [s for s in (first - a for a in names) if s % 0x4000 == 0
                  and all(g - s in names for g in seen)]
        if len(slides) != 1:
            print(f"{path}: cannot place the gadgets taken", file=sys.stderr)
            return False
        taken |= {names[g - slides[0]] for g in seen}
        gadgets = [names[g - slides[0]] for g in picked]
        unjoined |= {(a, b) for a, b in zip(gadgets, gadgets[1:])
                     if a in setters and b.startswith(setters[a])}

    want = {spec.name
            for spec in specs
            if (spec.ordered == (order == "ordered") or
                not getattr(spec, "accesses_memory", False))}
    missed = sorted(want - taken)
    for name in missed:
        print(f"never taken: rcg_gadget_{name}", file=sys.stderr)
    print(f"RCG: {len(want) - len(missed)} of {len(want)} {order} gadgets "
          f"taken", file=sys.stderr)
    for setter, jcc in sorted(unjoined):
        print(f"not joined: rcg_gadget_{setter}, then rcg_gadget_{jcc}",
              file=sys.stderr)
    return not missed and not unjoined
