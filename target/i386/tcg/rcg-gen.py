#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
""" RCG's gadget generator for x86-64 guests.

RCG, the rich code generator, runs a guest instruction under TCTI as one
gadget that does the whole instruction, where TCG would run a gadget for
each of its TCG ops. What each instruction does is written here once: the
tables below list every op, form and width there is a gadget for, with the
lazy-flags facts a translator needs to use them, and the body of each
gadget loads its operands from env or guest memory, computes, then writes
the result and the flags state. The translator is not here; where these
tables say what "the translator" does, they say what it must do.

How a gadget is entered, how it gets its operand words and how it leaves
are a harness's business, not the body's (see Harness), so that the same
bodies can run under more than one harness: a gadget is a harness around a
body.

The same tables give the x86-64 system tests that check RCG against TCG,
which run every form over awkward values and fault in the middle of every
memory form. This writes the cases of rcg-insns.c or rcg-faults.c (in
tests/tcg/x86_64/system) to a file. --check renders every gadget's body and
checks what it names, and --gadgets writes TCTI's gadgets and
rcg-table.c.inc, the translator's table of them, to a directory.
--coverage checks that the tests ran every gadget (see check_coverage()):

    rcg-gen.py --insn-tests FILE
    rcg-gen.py --fault-tests FILE
    rcg-gen.py --check
    rcg-gen.py --gadgets DIR
    rcg-gen.py --coverage ordered|plain NM TRACE...

Only 64-bit code is covered, without LOCK; anything else is left to TCG.
"""

import argparse
import os
import re
import sys

# The source tree's root, three levels above this file.
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")

# The guest-memory templates are TCTI's, so that RCG's accesses look the
# address up, call cputlb and keep the guest's memory order exactly as
# TCTI's do. They are imported without leaving bytecode in the source tree.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(SRC, "tcg", "aarch64-tcti"))
import tcti_memory  # noqa: E402


#
# The guest's side: registers, widths and addresses.
#

# x86 register numbers, as decode-new and CPUX86State.regs[] use them.
REGS64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
R_ESP = 4

WIDTHS = (8, 16, 32, 64)
PTR = {8: "byte", 16: "word", 32: "dword", 64: "qword"}
MO = {8: "MO_8", 16: "MO_16", 32: "MO_32", 64: "MO_64"}


def reg_name(n, width):
    """ The name of register n at width, the low byte for 8 bits. """
    if width == 64:
        return REGS64[n]
    if n >= 8:
        return REGS64[n] + {32: "d", 16: "w", 8: "b"}[width]
    if width == 32:
        return "e" + REGS64[n][1:]
    if width == 16:
        return REGS64[n][1:]
    return {0: "al", 1: "cl", 2: "dl", 3: "bl",
            4: "spl", 5: "bpl", 6: "sil", 7: "dil"}[n]


# The guest addressing modes a memory operand's gadget takes, by how the
# effective address is formed: base + disp ("b"), base + (index << scale)
# + disp ("bi" and the scale), (index << scale) + disp ("i" and the scale),
# or disp alone ("d"). A RIP-relative address is "b" on env's eip, as TCG
# makes it under CF_PCREL, or "d". Each comes with and without the base of
# FS or GS added ("seg"), the only segment bases 64-bit code has.
EA_SHAPES = ("b", "bi0", "bi1", "bi2", "bi3", "i0", "i1", "i2", "i3", "d")
EA_SEGS = (False, True)


def ea_words(shape, seg):
    """ The operand words a memory operand of shape takes, in order: env
    offsets of the base and index registers, the displacement, then the env
    offset of the segment base. """
    words = []
    if shape.startswith("b"):
        words.append("base")
    if "i" in shape:
        words.append("index")
    words.append("disp")
    if seg:
        words.append("seg")
    return words


#
# The tables: what there is a gadget for.
#

class Alu:
    """ A two-operand ALU instruction: dest = dest op src. The result is
    written back unless writes is false (CMP and TEST). cc is the lazy-flags
    state it leaves, as TCG's gen_<name> does: "ADD", "SUB" or "LOGIC", for
    CC_OP_<cc>B plus the width's MemOp. """

    def __init__(self, name, a64, cc, writes, forms):
        self.name = name
        self.a64 = a64
        self.cc = cc
        self.writes = writes
        self.forms = forms


ALU_FORMS = ("rr", "rm", "mr", "ri", "mi")

ALU_OPS = (
    Alu("add",  "add", "ADD",   True,  ALU_FORMS),
    Alu("sub",  "sub", "SUB",   True,  ALU_FORMS),
    Alu("and",  "and", "LOGIC", True,  ALU_FORMS),
    Alu("or",   "orr", "LOGIC", True,  ALU_FORMS),
    Alu("xor",  "eor", "LOGIC", True,  ALU_FORMS),
    Alu("cmp",  "sub", "SUB",   False, ALU_FORMS),
    Alu("test", "and", "LOGIC", False, ("rr", "mr", "ri", "mi")),
)

# MOV's forms: dest = src, flags untouched.
MOV_FORMS = ("rr", "rm", "mr", "ri", "mi")

# LEA's widths: there is no 8-bit LEA.
LEA_WIDTHS = (16, 32, 64)


class Extend:
    """ MOVZX, MOVSX and MOVSXD: dest = the src bits of the source, zero- or
    sign-extended, written at the operand size (each of widths); flags
    untouched. """

    def __init__(self, name, src, signed, widths):
        self.name = name
        self.src = src
        self.signed = signed
        self.widths = widths


EXTEND_OPS = (
    Extend("movzxb", 8,  False, (16, 32, 64)),
    Extend("movzxw", 16, False, (32, 64)),
    Extend("movsxb", 8,  True,  (16, 32, 64)),
    Extend("movsxw", 16, True,  (32, 64)),
    Extend("movsxd", 32, True,  (64,)),
)


class Unary:
    """ NOT, NEG, INC and DEC: dest = op dest, a64 being the AArch64
    instruction that computes {r} from {a}. NEG leaves CC_OP_SUB as gen_NEG
    does, with cc_srcT 0; NOT leaves the flags alone. INC and DEC leave
    CC_OP_INC and CC_OP_DEC with cc_dst the result, and keep CF, which
    gen_INC and gen_DEC put in cc_src: the gadget leaves cc_src alone, and
    the translator must put CF from before the instruction in it. """

    def __init__(self, name, a64, cc):
        self.name = name
        self.a64 = a64
        self.cc = cc

    @property
    def keeps_cf(self):
        return self.cc in ("INC", "DEC")


UNARY_OPS = (
    Unary("not", "mvn {r}, {a}",     None),
    Unary("neg", "neg {r}, {a}",     "SUB"),
    Unary("inc", "add {r}, {a}, #1", "INC"),
    Unary("dec", "sub {r}, {a}, #1", "DEC"),
)


class Shift:
    """ SHL, SHR and SAR by an immediate count (or 1): dest = dest shifted,
    on the value zero-extended (SAR: sign-extended) from the operand size as
    TCG's ZExtT0 and SExtT0 load it, with cc_dst the result and cc_src the
    value shifted by one less, as gen_SHL and friends leave them. The count
    is a word, which the translator must mask, and a count that masks to 0
    must be left to TCG: cc_src would be the value shifted by count - 1,
    that is by -1. """

    def __init__(self, name, a64, cc):
        self.name = name
        self.a64 = a64
        self.cc = cc

    @property
    def signed(self):
        return self.name == "sar"


SHIFT_OPS = (
    Shift("shl", "lsl", "SHL"),
    Shift("shr", "lsr", "SAR"),
    Shift("sar", "asr", "SAR"),
)

# ROR of a register by an immediate count, at 32 and 64 bits, which also does
# ROL as ROR by the width less the count. Its cc_op is None because the
# gadget leaves the flags state alone, not because the instruction does: the
# translator must have TCG compute the CF and OF the instruction leaves, by
# ROL's rule for a ROL (CF the result's bit 0) and ROR's for a ROR (CF its
# top bit), which TCG drops when nothing reads them. As for the shifts, a
# count that masks to 0 must be left to TCG.
ROTATE_OP = Shift("ror", "ror", None)
ROTATE_WIDTHS = (32, 64)


# The lazy-flags states a condition can be read from without a helper, as
# TCG's CC_OP_<class>B + the width's MemOp, or CC_OP_EFLAGS alone.
CC_CLASSES = ([(cls, width) for cls in ("sub", "add", "logic", "inc", "dec")
               for width in WIDTHS] + [("eflags", None)])

# x86 conditions by the low four bits of Jcc's, SETcc's and CMOVcc's opcode.
CONDS = ("o", "no", "b", "ae", "e", "ne", "be", "a",
         "s", "ns", "p", "np", "l", "ge", "le", "g")

# CMOVcc's widths.
CMOV_WIDTHS = (16, 32, 64)


def cc_name(cls, width):
    return cls + (str(width) if width else "")


class CondSpec:
    """ One gadget that reads a condition from the lazy-flags state cls at
    width, left by an instruction before it in the TB: kind "jcc" (stores
    CC_OP, then branches), "setcc" (an 8-bit register) or "cmov" (register
    to register at width cmov_width). """

    def __init__(self, kind, cls, cc_width, cond, cmov_width=None):
        self.kind = kind
        self.cls = cls
        self.cc_width = cc_width
        self.cond = cond
        self.cmov_width = cmov_width
        self.has_mem = False
        self.shape = None
        self.ordered = False

    @property
    def name(self):
        parts = [self.kind]
        if self.cmov_width:
            parts.append(str(self.cmov_width))
        parts += [cc_name(self.cls, self.cc_width), CONDS[self.cond]]
        return "_".join(parts)

    @property
    def words(self):
        if self.kind == "jcc":
            return ["ccop"]
        if self.kind == "setcc":
            return ["d"]
        return ["d", "s"]


def cond_specs():
    """ Every condition gadget there is: P and NP only from CC_OP_EFLAGS. """
    for cls, width in CC_CLASSES:
        for cond in range(16):
            if cond >> 1 == 5 and cls != "eflags":
                continue
            yield CondSpec("jcc", cls, width, cond)
            yield CondSpec("setcc", cls, width, cond)
            for cmov_width in CMOV_WIDTHS:
                yield CondSpec("cmov", cls, width, cond, cmov_width)


class Spec:
    """ One gadget: what it does and the words it takes.

    kind is "alu", "zero" (XOR of a register with itself), "mov", "lea",
    "push", "pop", "extend", "unary", "shift", "call", "jmp" or "ret".
    form is the destination's kind then the source's (r, m or i); for CALL
    and JMP it is the target's (i for CALL rel32), and for RET i. shape and
    seg are the memory operand's, if any. ordered is for the twin that keeps
    the guest's memory order (tcg_ldst_ordered()).
    """

    def __init__(self, kind, op, form, width, shape=None, seg=False,
                 ordered=False):
        self.kind = kind
        self.op = op
        self.form = form
        self.width = width
        self.shape = shape
        self.seg = seg
        self.ordered = ordered

    @property
    def has_mem(self):
        return self.shape is not None

    @property
    def name(self):
        """ The gadget's name, by which the translator picks it. """
        parts = [self.op.name if self.op else self.kind, self.form,
                 str(self.width)]
        if self.has_mem:
            parts.append(self.shape + ("_seg" if self.seg else ""))
        if self.ordered:
            parts.append("ord")
        return "_".join(parts)

    @property
    def reads_d(self):
        """ Whether the gadget reads its "d" register as well as writing
        it. """
        return self.kind in ("alu", "unary", "shift")

    @property
    def accesses_memory(self):
        # LEA's memory operand is only an address.
        return (self.has_mem and self.kind != "lea"
                or self.kind in ("push", "pop", "call", "ret"))

    @property
    def loads(self):
        """ Whether the gadget loads from guest memory: MOV to memory only
        stores. """
        if self.kind in ("pop", "ret"):
            return True
        return (self.has_mem and self.kind != "lea" and
                not (self.kind == "mov" and self.form[0] == "m"))

    @property
    def stores(self):
        """ Whether the gadget stores to guest memory: CMP and TEST, and a
        memory source, only load. """
        if self.kind in ("push", "call"):
            return True
        return (self.has_mem and self.form[0] == "m" and
                (self.kind in ("mov", "unary", "shift") or
                 self.kind == "alu" and self.op.writes))

    @property
    def words(self):
        """ The gadget's operand words, in the order the translator must give
        them: the destination's, then the source's, then for a memory access
        the MemOpIdx and the env offset of the MMU index's CPUTLBDescFast
        (what TCTI_TLB_FAST_OFS() gives). A register operand is its env
        offset in CPUX86State.regs[]: "d" if it is written, "s" if only read,
        and "s1" for CMP's and TEST's first operand, which is only read. A
        memory operand is the words of its shape (ea_words()). An immediate
        is its value, sign-extended as decode-new extends it.

        CALL's imm is the return address less env's eip, and RET's how far
        it moves RSP. """
        if self.kind in ("call", "jmp", "ret"):
            words = (ea_words(self.shape, self.seg) if self.form == "m"
                     else ["s"] if self.form == "r" else [])
            if self.kind != "jmp":
                words.append("imm")
            if self.accesses_memory:
                words += ["oi", "tlb"]
            return words
        if self.kind == "push":
            operands = ["s" if self.form == "r" else self.form]
        elif self.kind in ("pop", "unary"):
            operands = ["d" if self.form == "r" else self.form]
        else:
            operands = ["d" if self.form[0] == "r" else self.form[0]]
            if self.kind != "zero":
                operands.append("s" if self.form[1] == "r" else self.form[1])
            if self.kind == "alu" and not self.op.writes and operands[0] == "d":
                operands[0] = "s1"
        words = []
        for operand in operands:
            if operand == "m":
                words += ea_words(self.shape, self.seg)
            elif operand == "i":
                words.append("imm")
            else:
                words.append(operand)
        if self.accesses_memory:
            words += ["oi", "tlb"]
        return words

    @property
    def cc_op(self):
        """ The CC_OP the gadget leaves, as a C expression, or None if the
        gadget leaves the flags state alone. For ROR the instruction still
        changes the flags; see ROTATE_OP. """
        if self.kind == "zero":
            return "CC_OP_EFLAGS"
        if self.kind in ("alu", "unary", "shift") and self.op.cc:
            return f"CC_OP_{self.op.cc}B + {MO[self.width]}"
        return None

    @property
    def cc_writes(self):
        """ Which of cc_dst, cc_src and cc_src2 the gadget writes, as TCG's
        decode.cc_dst, cc_src and cc_src2 say for the instruction. After a
        "SUB" one, the translator must also keep cc_srcT = cc_dst + cc_src,
        the original first operand, as TCG's gen_SUB does (0 after NEG,
        which is the same sum). INC and DEC write cc_dst alone; see Unary. """
        if self.kind == "zero":
            return ("cc_src",)
        if self.kind == "alu":
            if self.op.cc == "LOGIC":
                return ("cc_dst",)
            return ("cc_dst", "cc_src")
        if self.kind == "unary" and self.op.keeps_cf:
            return ("cc_dst",)
        if self.kind in ("unary", "shift") and self.op.cc:
            return ("cc_dst", "cc_src")
        return ()


def specs():
    """ Every gadget there is. """
    for op in ALU_OPS:
        for form in op.forms:
            for width in WIDTHS:
                yield from with_memory(Spec("alu", op, form, width))
    for width in WIDTHS:
        yield Spec("zero", None, "rr", width)
    for form in MOV_FORMS:
        for width in WIDTHS:
            yield from with_memory(Spec("mov", None, form, width))
    for width in LEA_WIDTHS:
        for shape in EA_SHAPES:
            yield Spec("lea", None, "rm", width, shape)
    for form in ("r", "i", "m"):
        yield from with_memory(Spec("push", None, form, 64))
    yield from with_memory(Spec("pop", None, "r", 64))
    for op in EXTEND_OPS:
        for form in ("rr", "rm"):
            for width in op.widths:
                yield from with_memory(Spec("extend", op, form, width))
    for op in UNARY_OPS:
        for form in ("r", "m"):
            for width in WIDTHS:
                yield from with_memory(Spec("unary", op, form, width))
    for op in SHIFT_OPS:
        for form in ("ri", "mi"):
            for width in WIDTHS:
                yield from with_memory(Spec("shift", op, form, width))
    for width in ROTATE_WIDTHS:
        yield Spec("shift", ROTATE_OP, "ri", width)
    for form in ("i", "r", "m"):
        yield from with_memory(Spec("call", None, form, 64))
    for form in ("r", "m"):
        yield from with_memory(Spec("jmp", None, form, 64))
    yield from with_memory(Spec("ret", None, "i", 64))


def with_memory(spec):
    """ spec with each memory operand shape, if it has one, and each
    memory-order twin, if it accesses memory. """
    shapes = [None]
    if "m" in spec.form:
        shapes = [(shape, seg) for shape in EA_SHAPES for seg in EA_SEGS]
    for shape in shapes:
        for ordered in (False, True):
            s = Spec(spec.kind, spec.op, spec.form, spec.width,
                     *(shape or (None, False)), ordered)
            if ordered and not s.accesses_memory:
                continue
            yield s


#
# The host's side: the gadget bodies.
#

# A gadget's operand words arrive in these registers, in order. They are
# none of x0-x4, which a slow path sets up as a helper's arguments before it
# is done with the words.
WORD_REGS = ("x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12")

# What a body computes in: the address, the first and second operands, the
# result, and scratch.
ADDR, A, B, R, T = "x0", "x1", "x2", "x3", "x4"

# The memory templates' output: the TLB addend after a fast path, and the
# value after a load's slow path.
OUT = tcti_memory.TMP[1]

# Loads by width: the plain access, from [addr, addend]; the ordered one
# (LDAPR), from the host address, which the template leaves in OUT; and the
# cputlb helper for the slow path. Both accesses zero-extend, as TCG's loads
# of x86 operands do. STORES is the same for stores, with STLR.
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
    keeps what it needs across that call with save and restore. """

    env = "x14"
    retaddr = "x28"
    save = tcti_memory.C_CALL_PROLOGUE
    restore = tcti_memory.C_CALL_EPILOGUE
    scratch = (*(f"x{n}" for n in range(14)), *tcti_memory.TMP)

    def enter(self, regs):
        """ The lines that load the gadget's operand words into regs. """
        raise NotImplementedError

    def leave(self):
        """ The lines that end the gadget, going on to what follows it. """
        raise NotImplementedError

    def branch(self, arm):
        """ The lines that make the gadget go on at its target instead, if
        the host's condition arm holds. """
        raise NotImplementedError

    def assemble(self, words, hot, cold):
        """ The whole gadget, from the words' registers, the body's lines on
        the way through and its slow paths. """
        return [*self.enter(words), *hot, *self.leave(), *cold]


class Body:
    """ A gadget body as it is written: the lines on the way through (hot),
    and the slow paths, which go after the gadget's end and branch back
    (cold). """

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
        self.reads = set()

    def word(self, name):
        return self.word_regs[name]

    def emit(self, *lines):
        self.hot.extend(lines)

    def define(self, *regs):
        """ Notes that regs hold values from here on, for the slow paths
        that follow to keep. """
        self.used.update(regs)

    def lines(self):
        """ The whole gadget. """
        return self.h.assemble(list(self.word_regs.values()), self.hot,
                               self.cold)

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
        save, restore = self._save(self.used | set(self.word_regs.values()))
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
        save, restore = self._save(self.used | set(self.word_regs.values()))
        self.cold += [
            *tcti_memory.store_slow_path(
                helper, self._memop(), w(value) if width < 64 else value,
                addr=addr, ordered=size if ordered else None,
                miss_label=miss, env=self.env, retaddr=self.h.retaddr,
                save=save, restore=restore),
            f"b {join}b",
        ]

    def ea(self, dest, with_seg=True):
        """ dest = the memory operand's effective address, as TCG's
        gen_lea_modrm_1() and gen_lea_v_seg() form it for 64-bit code: the
        base, plus the index shifted by the scale, plus the displacement,
        plus the segment base if there is one. """
        shape, env = self.spec.shape, self.env
        terms = []
        if shape.startswith("b"):
            self.emit(f"ldr {dest}, [{env}, {self.word('base')}]")
            terms.append(dest)
        if "i" in shape:
            scale = int(shape[-1])
            self.emit(f"ldr {T}, [{env}, {self.word('index')}]")
            if terms:
                self.emit(f"add {dest}, {dest}, {T}, lsl #{scale}")
            else:
                self.emit(f"lsl {dest}, {T}, #{scale}")
            terms.append(dest)
        if terms:
            self.emit(f"add {dest}, {dest}, {self.word('disp')}")
        else:
            self.emit(f"mov {dest}, {self.word('disp')}")
        if self.spec.seg and with_seg:
            self.emit(f"ldr {T}, [{env}, {self.word('seg')}]",
                      f"add {dest}, {dest}, {T}")
        self.define(dest)

    def read_reg(self, dest, word):
        """ dest = the whole register whose env offset is in word, as TCG's
        gen_op_mov_v_reg() reads it for any width (the high-byte registers
        AH to BH are left to TCG). """
        self.emit(f"ldr {dest}, [{self.env}, {self.word(word)}]")
        self.define(dest)
        self.reads.add(word)

    def write_reg(self, value, word, width):
        """ The width bits of value to the register whose env offset is in
        word, as TCG's gen_op_mov_reg_v() writes them: 8 and 16 bits into
        the low part, keeping the rest; 32 bits zero-extended. """
        ofs = self.word(word)
        if width == 8:
            self.emit(f"strb {w(value)}, [{self.env}, {ofs}]")
        elif width == 16:
            self.emit(f"strh {w(value)}, [{self.env}, {ofs}]")
        elif width == 32 and value != "xzr":
            self.emit(f"mov {w(T)}, {w(value)}",
                      f"str {T}, [{self.env}, {ofs}]")
        else:
            self.emit(f"str {value}, [{self.env}, {ofs}]")

    def extend(self, reg, width, signed):
        """ reg = its low width bits, zero- or sign-extended to 64. """
        if width == 64:
            return
        op = {8: "b", 16: "h", 32: "w"}[width]
        if signed:
            self.emit(f"sxt{op} {reg}, {w(reg)}")
        elif width == 32:
            self.emit(f"mov {w(reg)}, {w(reg)}")
        else:
            self.emit(f"uxt{op} {w(reg)}, {w(reg)}")

    def cond(self, cls, width, cond):
        """ Sets the host's flags from the lazy-flags state cls at width
        (as CC_OP_<cls>B + the width's MemOp would read), and returns the
        AArch64 condition under which x86 condition cond holds. Values are
        compared shifted to the top of a register, so that the host's N, Z,
        C and V are the guest's at width. """
        env, jcc_op, inv = self.env, cond >> 1, cond & 1
        shift = 64 - width if width else 0

        def top(reg):
            if shift:
                self.emit(f"lsl {reg}, {reg}, #{shift}")

        never = None
        if cls == "eflags":
            # The flags themselves, in cc_src.
            self.emit(f"ldr {A}, [{env}, %[cc_src]]")
            masks = {0: "CC_O", 1: "CC_C", 2: "CC_Z", 3: "CC_Z | CC_C",
                     4: "CC_S", 5: "CC_P"}
            if jcc_op == 3:
                # Not a logical immediate.
                self.emit(f"mov {T}, %[eflags_3]",
                          f"tst {A}, {T}")
            elif jcc_op in masks:
                self.emit(f"tst {A}, %[eflags_{jcc_op}]")
            else:
                # SF != OF, or with ZF: OF is 4 bits above SF, ZF one below.
                self.emit(f"eor {T}, {A}, {A}, lsr #4")
                if jcc_op == 7:
                    self.emit(f"orr {T}, {T}, {A}, lsl #1")
                self.emit(f"tst {T}, %[cc_s]")
            arm = "ne"
        elif cls == "logic" and jcc_op in (0, 1):
            # OF and CF are 0.
            never = True
        else:
            self.emit(f"ldp {A}, {B}, [{env}, %[cc_dst]]")
            if cls in ("sub", "add"):
                # SUB: cc_dst + cc_src is cc_srcT, the first operand; ADD:
                # cc_dst - cc_src is it.
                self.emit(f"{'add' if cls == 'sub' else 'sub'} {A}, {A}, {B}")
                top(A)
                top(B)
                self.emit(f"{'cmp' if cls == 'sub' else 'cmn'} {A}, {B}")
                arms = ({0: "vs", 1: "lo", 2: "eq", 3: "ls", 4: "mi", 6: "lt",
                         7: "le"} if cls == "sub" else
                        {0: "vs", 1: "cs", 2: "eq", 4: "mi", 6: "lt", 7: "le"})
                if jcc_op == 3 and cls == "add":
                    # CF or ZF: 1 if Z, else C.
                    self.emit(f"cset {T}, cs",
                              f"csinc {T}, {T}, xzr, ne",
                              f"cmp {T}, #0")
                    arm = "ne"
                else:
                    arm = arms[jcc_op]
            elif cls == "logic":
                top(A)
                self.emit(f"tst {A}, {A}")
                arm = {2: "eq", 3: "eq", 4: "mi", 6: "lt", 7: "le"}[jcc_op]
            else:
                # INC and DEC: cc_src holds CF from before them. The other
                # flags come from doing the operation again on its operand,
                # cc_dst - 1 for INC and cc_dst + 1 for DEC.
                if jcc_op == 1:
                    self.emit(f"cmp {B}, #0")
                    arm = "ne"
                elif jcc_op == 3:
                    if shift:
                        self.emit(f"lsl {T}, {A}, #{shift}",
                                  f"cmp {T}, #0")
                    else:
                        self.emit(f"cmp {A}, #0")
                    self.emit(f"ccmp {B}, #0, #0, ne")
                    arm = "ne"
                else:
                    undo = "sub" if cls == "inc" else "add"
                    self.emit(f"{undo} {T}, {A}, #1")
                    top(T)
                    self.emit(f"mov {A}, #{1 << shift:#x}",
                              f"{'cmn' if cls == 'inc' else 'cmp'} {T}, {A}")
                    arm = {0: "vs", 2: "eq", 4: "mi", 6: "lt", 7: "le"}[jcc_op]
        if never:
            self.emit("cmp xzr, xzr")
            arm = "ne"
        if inv:
            arm = ARM_INVERT[arm]
        return arm

    def branch(self, arm):
        """ The harness's branch to the gadget's target if arm holds. """
        self.emit(*self.h.branch(arm))

    def write_cc(self, dst=None, src=None):
        """ The lazy-flags state: cc_dst and cc_src, whichever are given, from
        registers. """
        env = self.env
        if dst and src:
            # cc_src follows cc_dst in CPUX86State: one STP stores both.
            self.emit(f"stp {dst}, {src}, [{env}, %[cc_dst]]")
        elif dst:
            self.emit(f"str {dst}, [{env}, %[cc_dst]]")
        elif src:
            self.emit(f"str {src}, [{env}, %[cc_src]]")


def body(spec, harness):
    """ The lines of the gadget for spec, in harness. """
    g = Body(spec, harness)
    BODIES[spec.kind](g, spec)
    return g.lines()


def alu_body(g, spec):
    op, form, width = spec.op, spec.form, spec.width
    first = "d" if op.writes else "s1"
    if spec.has_mem:
        g.ea(ADDR)

    # Everything that can fault comes before any guest state is written:
    # the load, then the store, then the registers and the flags state.
    if form[0] == "m":
        g.load(A, ADDR, width)
    elif form[1] == "m":
        g.load(B, ADDR, width)
    if form[0] == "r":
        g.read_reg(A, first)
    if form[1] == "r":
        g.read_reg(B, "s")
    elif form[1] == "i":
        g.emit(f"mov {B}, {g.word('imm')}")
        g.define(B)

    # Whole registers, as TCG computes: only the flags state and the
    # write-back look at the width.
    g.emit(f"{op.a64} {R}, {A}, {B}")
    g.define(R)

    if op.writes:
        if form[0] == "m":
            g.store(R, ADDR, width)
        else:
            g.write_reg(R, "d", width)
    if op.cc == "LOGIC":
        g.write_cc(dst=R)
    else:
        g.write_cc(dst=R, src=B)


def zero_body(g, spec):
    # TCG's gen_XOR for a register with itself: 0, and flags of just ZF
    # and PF, as CC_OP_EFLAGS.
    g.write_reg("xzr", "d", spec.width)
    g.emit(f"mov {R}, %[cc_z_p]")
    g.write_cc(src=R)


def mov_body(g, spec):
    form, width = spec.form, spec.width
    if spec.has_mem:
        g.ea(ADDR)
    if form[1] == "m":
        g.load(A, ADDR, width)
    elif form[1] == "r":
        g.read_reg(A, "s")
    else:
        g.emit(f"mov {A}, {g.word('imm')}")
        g.define(A)
    if form[0] == "m":
        g.store(A, ADDR, width)
    else:
        g.write_reg(A, "d", width)


def lea_body(g, spec):
    # gen_LEA: the address without the segment base, at the operand size.
    g.ea(ADDR, with_seg=False)
    g.write_reg(ADDR, "d", spec.width)


def push_body(g, spec):
    # gen_push_v for 64-bit code: the value is read first (so PUSH RSP
    # pushes the old RSP), stored below RSP, and RSP is moved down only
    # once the store has been made.
    env = g.env
    if spec.form == "m":
        g.ea(ADDR)
        g.load(A, ADDR, 64)
    elif spec.form == "r":
        g.read_reg(A, "s")
    else:
        g.emit(f"mov {A}, {g.word('imm')}")
        g.define(A)
    g.emit(f"ldr {B}, [{env}, %[rsp]]", f"sub {B}, {B}, #8")
    g.define(B)
    g.store(A, B, 64)
    g.emit(f"str {B}, [{env}, %[rsp]]")


def pop_body(g, spec):
    # gen_POP for a register in 64-bit code: load from RSP, move RSP up,
    # then write the register, so that POP RSP leaves the value loaded.
    env = g.env
    g.emit(f"ldr {B}, [{env}, %[rsp]]")
    g.define(B)
    g.load(A, B, 64)
    g.emit(f"add {B}, {B}, #8", f"str {B}, [{env}, %[rsp]]")
    g.write_reg(A, "d", 64)


def call_body(g, spec):
    # gen_CALL's and gen_CALL_m's push of the return address, as push_body()
    # pushes; CALL_m's target is read first, and written to eip last. The
    # translator must end the TB after it, and for CALL rel jump itself.
    env = g.env
    if spec.form == "m":
        g.ea(ADDR)
        g.load(R, ADDR, 64)
        if not spec.ordered:
            # TCG's barrier before the plain twin orders only earlier
            # accesses. The push's store does not depend on the load, so
            # order the two here, as the barrier TCG puts before a store
            # would.
            g.emit("dmb ishld")
    elif spec.form == "r":
        g.read_reg(R, "s")
    g.emit(f"ldr {A}, [{env}, %[eip]]", f"add {A}, {A}, {g.word('imm')}",
           f"ldr {B}, [{env}, %[rsp]]", f"sub {B}, {B}, #8")
    g.define(A, B)
    g.store(A, B, 64)
    g.emit(f"str {B}, [{env}, %[rsp]]")
    if spec.form != "i":
        g.emit(f"str {R}, [{env}, %[eip]]")


def jmp_body(g, spec):
    # gen_JMP_m: the target to eip.
    if spec.form == "m":
        g.ea(ADDR)
        g.load(A, ADDR, 64)
    else:
        g.read_reg(A, "s")
    g.emit(f"str {A}, [{g.env}, %[eip]]")


def ret_body(g, spec):
    # gen_RET: the return address from the top of the stack, then RSP moved
    # up past it and RET's immediate, and the address to eip.
    env = g.env
    g.emit(f"ldr {B}, [{env}, %[rsp]]")
    g.define(B)
    g.load(A, B, 64)
    g.emit(f"add {B}, {B}, {g.word('imm')}", f"str {B}, [{env}, %[rsp]]",
           f"str {A}, [{env}, %[eip]]")


def extend_body(g, spec):
    # gen_MOV with ZExtT0 or SExtT0: the source read at its size, extended,
    # then written at the operand size.
    op = spec.op
    if spec.form == "rm":
        g.ea(ADDR)
        g.load(A, ADDR, op.src)
        if op.signed:
            g.extend(A, op.src, True)
    else:
        g.read_reg(A, "s")
        g.extend(A, op.src, op.signed)
    g.write_reg(A, "d", spec.width)


def unary_body(g, spec):
    # gen_NOT, gen_NEG, gen_INC and gen_DEC: on the whole register, written
    # at the operand size. INC's and DEC's cc_src is the translator's.
    op, width = spec.op, spec.width
    if spec.form == "m":
        g.ea(ADDR)
        g.load(A, ADDR, width)
    else:
        g.read_reg(A, "d")
    g.emit(op.a64.format(r=R, a=A))
    g.define(R)
    if spec.form == "m":
        g.store(R, ADDR, width)
    else:
        g.write_reg(R, "d", width)
    if op.keeps_cf:
        g.write_cc(dst=R)
    elif op.cc:
        g.write_cc(dst=R, src=A)


def shift_body(g, spec):
    # gen_SHL, gen_SHR and gen_SAR with a count known not to be 0: cc_src
    # is the value shifted by count - 1, cc_dst and the result by count.
    op, width = spec.op, spec.width
    if not op.cc:
        # ROR: a 32-bit ROR zero-extends, as the register write does.
        reg = w if width == 32 else (lambda r: r)
        g.read_reg(A, "d")
        count = g.word("imm")
        g.emit(f"ror {reg(R)}, {reg(A)}, {reg(count)}")
        g.define(R)
        g.write_reg(R, "d", 64)
        return
    if spec.form == "mi":
        g.ea(ADDR)
        g.load(A, ADDR, width)
        if op.signed:
            g.extend(A, width, True)
    else:
        g.read_reg(A, "d")
        g.extend(A, width, op.signed)
    count = g.word("imm")
    g.emit(f"sub {T}, {count}, #1",
           f"{op.a64} {B}, {A}, {T}",
           f"{op.a64} {R}, {A}, {count}")
    g.define(B, R)
    if spec.form == "mi":
        g.store(R, ADDR, width)
    else:
        g.write_reg(R, "d", width)
    g.write_cc(dst=R, src=B)


def jcc_body(g, spec):
    # gen_Jcc's condition and branch; the translator must emit the jumps on
    # either side. The gadget always stores CC_OP first, as gen_jcc() does
    # when cc_op is dirty, so that the translator need not.
    g.emit(f"str {w(g.word('ccop'))}, [{g.env}, %[cc_op]]")
    g.branch(g.cond(spec.cls, spec.cc_width, spec.cond))


def setcc_body(g, spec):
    # gen_SETcc to a register.
    arm = g.cond(spec.cls, spec.cc_width, spec.cond)
    g.emit(f"cset {R}, {arm}")
    g.write_reg(R, "d", 8)


def cmov_body(g, spec):
    # gen_CMOVcc register to register: the result is written either way,
    # so a 32-bit CMOVcc zero-extends even when it does not move.
    g.read_reg(ADDR, "d")
    g.emit(f"ldr {R}, [{g.env}, {g.word('s')}]")
    g.define(R)
    arm = g.cond(spec.cls, spec.cc_width, spec.cond)
    g.emit(f"csel {R}, {R}, {ADDR}, {arm}")
    g.write_reg(R, "d", spec.cmov_width)


BODIES = {
    "jcc": jcc_body,
    "setcc": setcc_body,
    "cmov": cmov_body,
    "extend": extend_body,
    "unary": unary_body,
    "shift": shift_body,
    "alu": alu_body,
    "zero": zero_body,
    "mov": mov_body,
    "lea": lea_body,
    "push": push_body,
    "pop": pop_body,
    "call": call_body,
    "jmp": jmp_body,
    "ret": ret_body,
}

# The "i" asm operands the bodies use, which the C compiler works out from
# QEMU's definitions. They are the TLB lookup's (see
# tcti_memory.tlb_operands()), with two changes: the CPUTLBDescFast's offset
# is a word instead, and the comparator is two operands, one to read and one
# to write, as a gadget may do both. Then come those the bodies use
# directly.
BODY_OPERANDS = {
    "tlb_shift": "TCTI_TLB_INDEX_SHIFT",
    "tlb_cmp_read": "offsetof(CPUTLBEntry, addr_read)",
    "tlb_cmp_write": "offsetof(CPUTLBEntry, addr_write)",
    "tlb_addend": "offsetof(CPUTLBEntry, addend)",
    "tlb_page_mask": "TCTI_TLB_PAGE_MASK",
    "cc_dst": "offsetof(CPUX86State, cc_dst)",
    "cc_src": "offsetof(CPUX86State, cc_src)",
    "rsp": f"offsetof(CPUX86State, regs[{R_ESP}])",
    "eip": "offsetof(CPUX86State, eip)",
    "cc_z_p": "CC_Z | CC_P",
    "cc_op": "offsetof(CPUX86State, cc_op)",
    "cc_s": "CC_S",
    "eflags_0": "CC_O",
    "eflags_1": "CC_C",
    "eflags_2": "CC_Z",
    "eflags_3": "CC_Z | CC_C",
    "eflags_4": "CC_S",
    "eflags_5": "CC_P",
}

# What the bodies take for granted of QEMU's definitions, beyond what their
# operands say, for code that builds the gadgets to check with
# QEMU_BUILD_BUG_ON.
BODY_ASSUMPTIONS = (
    # write_cc() and cond() access both with one STP or LDP.
    "offsetof(CPUX86State, cc_src) != offsetof(CPUX86State, cc_dst) + 8",
    # cond() tests L and LE on EFLAGS by shifting OF onto SF and SF onto ZF.
    "CC_O != CC_S << 4",
    "CC_S != CC_Z << 1",
)


class CheckHarness(Harness):
    """ A harness that only marks where a gadget is entered, branches and
    leaves, so that check() can render every body without building it. """

    def enter(self, regs):
        return [f"// enter: {', '.join(regs)}"]

    def leave(self):
        return ["// leave"]

    def branch(self, arm):
        return [f"// branch if {arm}"]


def check():
    """ Renders every gadget's body, the condition gadgets' included, and
    checks that each names only the asm operands of BODY_OPERANDS and the
    registers a body may use, that every branch it makes has a label to go
    to, and that it reads its "d" register only if reads_d says so. Returns
    how many gadgets were checked. """
    h = CheckHarness()
    allowed = {*h.scratch, h.env, h.retaddr, "x15", "sp", "lr", "xzr"}
    names = set()
    for spec in [*specs(), *cond_specs()]:
        assert spec.name not in names, spec.name
        names.add(spec.name)
        g = Body(spec, h)
        BODIES[spec.kind](g, spec)
        lines = g.lines()
        if isinstance(spec, Spec):
            assert ("d" in g.reads) == (spec.reads_d and "d" in spec.words), \
                spec.name
        labels = {line[:-1] for line in lines if re.fullmatch(r"\d+:", line)}
        for line in lines:
            if line.startswith("//"):
                continue
            for operand in re.findall(r"%\[(\w+)\]", line):
                assert operand in BODY_OPERANDS, (spec.name, line)
            for reg in re.findall(r"\b([xw](?:\d+|zr)|sp|lr)\b", line):
                assert "x" + reg[1:] in allowed or reg in allowed, \
                    (spec.name, line)
            for target in re.findall(r"\b(\d+)[bf]\b", line):
                assert target in labels, (spec.name, line)
    return len(names)


#
# TCTI's gadgets, and the translator's table of them.
#

class TctiHarness(Harness):
    """ TCTI's streams: tcg_out_rich() writes a gadget's address, then its
    operand words. The gadget loads the words first, so x28, the return
    address its slow paths pass, points past them. """

    def enter(self, regs):
        lines = [f"ldp {a}, {b}, [x28], #16"
                 for a, b in zip(regs[::2], regs[1::2])]
        if len(regs) % 2:
            lines.append(f"ldr {regs[-1]}, [x28], #8")
        return lines

    def leave(self):
        return ["ldr x27, [x28], #8", "br x27"]

    def branch(self, arm):
        # tcg_out_rich_br() writes the target after the words. Branching,
        # rather than a CSEL into x28, lets the gadgets that follow run
        # ahead on the predicted path instead of waiting for the condition.
        return ["ldr x27, [x28], #8", f"b.{ARM_INVERT[arm]} 1f",
                "mov x28, x27", "1:"]

    def assemble(self, words, hot, cold):
        # A body with no slow path that leaves x27 and x28 alone loads the
        # next gadget's address before its body, as tcti-gadget-gen.py's
        # simple() does, so the dispatch target is known sooner.
        if cold or any(re.search(r"\b[xw]2[78]\b", line) for line in hot):
            return super().assemble(words, hot, cold)
        return [*self.enter(words), "ldr x27, [x28], #8", *hot, "br x27"]


# The ops and forms as the translator names them, in the table's order.
OP_NAMES = ("add", "sub", "and", "or", "xor", "cmp", "test", "zero", "mov",
            "lea", "push", "pop", "movzxb", "movzxw", "movsxb", "movsxw",
            "movsxd", "not", "neg", "inc", "dec", "shl", "shr", "sar", "ror",
            "call", "jmp", "ret")
FORM_NAMES = ("rr", "rm", "mr", "ri", "mi", "r", "i", "m")
KIND_NAMES = ("alu", "zero", "mov", "lea", "push", "pop", "extend", "unary",
              "shift", "call", "jmp", "ret")
WORD_NAMES = ("d", "s", "s1", "base", "index", "disp", "seg", "imm", "oi",
              "tlb", "ccop")
MAX_WORDS = len(WORD_REGS)

# The gadget source files, split by op so they compile in parallel; "other"
# takes the ops with no file.
# Must match target/i386/tcg/meson.build.
GADGET_FILES = ("add", "sub", "and", "or", "xor", "cmp", "test", "mov",
                "other", "shift", "jcc", "setcc", "cmov")


def op_name(spec):
    return spec.op.name if spec.op else spec.kind


def gadget_file(spec):
    if isinstance(spec, CondSpec):
        return spec.kind
    name = op_name(spec)
    if spec.kind == "shift":
        return "shift"
    return name if name in GADGET_FILES else "other"


def table_index(spec, nb_shapes):
    """ Where spec is in its op and form's gadgets, which are indexed by
    width (MemOp), shape, segment base and memory order. """
    width = WIDTHS.index(spec.width)
    shape = EA_SHAPES.index(spec.shape) if spec.has_mem else 0
    return ((width * nb_shapes + shape) * 2 + spec.seg) * 2 + spec.ordered


def write_gadgets(outdir):
    """ Writes the gadgets, in TCTI's harness, as naked functions, and their
    table to outdir. """
    harness = TctiHarness()
    operands = ", ".join(f'[{k}] "i" ({v})' for k, v in BODY_OPERANDS.items())
    all_specs = list(specs())
    conds = list(cond_specs())

    files = {}
    for name in GADGET_FILES:
        f = open(os.path.join(outdir, f"rcg_gadgets_{name}.c"), "w")
        print("/* Automatically generated by rcg-gen.py. Do not edit. */\n",
              file=f)
        print('#include "qemu/osdep.h"', file=f)
        print('#include "cpu.h"', file=f)
        print('#include "tcti-gadget-defs.h"\n', file=f)
        files[name] = f

    instructions = 0
    for spec in all_specs + conds:
        f = files[gadget_file(spec)]
        lines = body(spec, harness)
        instructions += sum(1 for line in lines
                            if not line.endswith(":") and
                            not line.startswith("."))
        print(f"void rcg_gadget_{spec.name}(void);", file=f)
        print(f"__attribute__((naked)) void rcg_gadget_{spec.name}(void)",
              file=f)
        print("{\n    asm(", file=f)
        for line in lines:
            print(f'        "{line}\\n"', file=f)
        print(f"        :: {operands});\n}}\n", file=f)
    for f in files.values():
        f.close()

    with open(os.path.join(outdir, "rcg-table.c.inc"), "w") as out:
        write_table(all_specs, out)
        write_cond_table(conds, out)

    sys.stderr.write(f"RCG: {len(all_specs) + len(conds)} gadgets with "
                     f"{instructions} "
                     f"instructions (~{instructions * 4 // 1024} KiB).\n")


def write_cond_table(conds, out):
    """ The condition gadgets, by the lazy-flags state they read
    (RCG_CC_*), their condition (the opcode's low four bits), and for CMOVcc
    the width as a MemOp. """
    p = lambda *a: print(*a, file=out)
    p("\n/* The lazy-flags states condition gadgets read: rcg-gen.py's "
      "CC_CLASSES. */")
    p("enum {")
    for cls, width in CC_CLASSES:
        p(f"    RCG_CC_{cc_name(cls, width).upper()},")
    p("    RCG_NB_CC,\n};\n")
    for spec in conds:
        p(f"void rcg_gadget_{spec.name}(void);")
    p("")
    index = {c: i for i, c in enumerate(CC_CLASSES)}

    def entry(spec):
        return f"rcg_gadget_{spec.name}"

    p("static const void *const rcg_jcc[RCG_NB_CC][16] = {")
    for spec in conds:
        if spec.kind == "jcc":
            p(f"    [{index[(spec.cls, spec.cc_width)]}][{spec.cond}] = "
              f"{entry(spec)},")
    p("};\n")
    p("static const void *const rcg_setcc[RCG_NB_CC][16] = {")
    for spec in conds:
        if spec.kind == "setcc":
            p(f"    [{index[(spec.cls, spec.cc_width)]}][{spec.cond}] = "
              f"{entry(spec)},")
    p("};\n")
    p("static const void *const rcg_cmov[MO_64 + 1][RCG_NB_CC][16] = {")
    for spec in conds:
        if spec.kind == "cmov":
            p(f"    [{MO[spec.cmov_width]}][{index[(spec.cls, spec.cc_width)]}]"
              f"[{spec.cond}] = {entry(spec)},")
    p("};")


def write_table(all_specs, out):
    """ The translator's gadget table, by op, form, width, shape, segment
    base and memory order, with each gadget's words and each op's lazy-flags
    facts. """
    p = lambda *a: print(*a, file=out)
    p("/* Automatically generated by rcg-gen.py. Do not edit. */\n")
    p("/* What the bodies assume of QEMU's definitions. */")
    for assumption in BODY_ASSUMPTIONS:
        p(f"QEMU_BUILD_BUG_ON({assumption});")
    p("")
    p("enum {")
    p("    RCG_W_END,")
    for w in WORD_NAMES:
        p(f"    RCG_W_{w.upper()},")
    p("};")
    p(f"#define RCG_MAX_WORDS {MAX_WORDS}\n")
    p("typedef enum RCGOp {")
    for name in OP_NAMES:
        p(f"    RCG_OP_{name.upper()},")
    p("    RCG_NB_OPS,\n} RCGOp;\n")
    p("typedef enum RCGForm {")
    for name in FORM_NAMES:
        p(f"    RCG_FORM_{name.upper()},")
    p("    RCG_NB_FORMS,\n} RCGForm;\n")
    p("/* A memory operand's shape; see rcg-gen.py's EA_SHAPES. */")
    p("typedef enum RCGShape {")
    for name in EA_SHAPES:
        p(f"    RCG_EA_{name.upper()},")
    p("    RCG_NB_SHAPES,\n} RCGShape;\n")
    p("typedef struct RCGGadget {")
    p("    const void *gadget;")
    p("    uint8_t words[RCG_MAX_WORDS];")
    p("} RCGGadget;\n")
    p("/* What an op and form's gadgets do to guest memory. */")
    p("enum {")
    p("    RCG_LOAD = 1,")
    p("    RCG_STORE = 2,")
    p("};\n")
    p("/*")
    p(" * An op and form's gadgets, indexed [width][shape][seg][ordered], the")
    p(" * width as a MemOp; one shape where there is no memory operand.")
    p(" * access: RCG_LOAD, RCG_STORE or both; 0 if none.")
    p(" */")
    p("typedef struct RCGSlot {")
    p("    const RCGGadget *gadgets;")
    p("    uint8_t nb_shapes;")
    p("    uint8_t access;")
    p("} RCGSlot;\n")
    p("/* An op's kind: rcg-gen.py's Spec.kind. */")
    p("typedef enum RCGKind {")
    for name in KIND_NAMES:
        p(f"    RCG_KIND_{name.upper()},")
    p("} RCGKind;\n")
    p("/* What the translator puts in cc_srcT after an op. */")
    p("enum {")
    p("    RCG_SRCT_NONE,")
    p("    RCG_SRCT_SUM,   /* cc_dst + cc_src, the original first operand */")
    p("    RCG_SRCT_ZERO,")
    p("};\n")
    p("/*")
    p(" * What the translator needs to know of an op. stack: it moves RSP.")
    p(" * branch: it ends the TB. Its gadget sets eip, except CALL rel's,")
    p(" * whose jump TCG emits. src_ot: the source's MemOp where it is not")
    p(" * the op's (MOVZX, MOVSX and MOVSXD), else -1. reads_d: its gadget")
    p(" * reads the destination register as well as writing it.")
    p(" *")
    p(" * Its lazy flags. cc_op: the CC_OP it leaves, plus the width's MemOp")
    p(" * if by_width; -1 if none, and for ROR, whose CF and OF the")
    p(" * translator computes. srcT: what the translator puts in cc_srcT")
    p(" * after it, as gen_SUB and gen_NEG do. dst, src: whether it writes")
    p(" * cc_dst and cc_src. cf: whether the translator puts CF from before")
    p(" * it in cc_src, as gen_INC and gen_DEC do.")
    p(" */")
    p("typedef struct RCGFacts {")
    p("    RCGKind kind;")
    p("    bool stack, branch;")
    p("    int8_t src_ot;")
    p("    bool reads_d;")
    p("    int cc_op;")
    p("    bool by_width;")
    p("    uint8_t srcT;")
    p("    bool dst, src, cf;")
    p("} RCGFacts;\n")

    for spec in all_specs:
        p(f"void rcg_gadget_{spec.name}(void);")
    p("")

    slots = {}
    for spec in all_specs:
        slots.setdefault((op_name(spec), spec.form), []).append(spec)
    access = {}
    for (op, form), group in slots.items():
        nb_shapes = len(EA_SHAPES) if group[0].has_mem else 1
        entries = [None] * (len(WIDTHS) * nb_shapes * 4)
        for spec in group:
            assert spec.accesses_memory == (spec.loads or spec.stores)
            entries[table_index(spec, nb_shapes)] = spec
        # The translator reads these per op and form.
        kinds = {(spec.loads, spec.stores) for spec in group}
        assert len(kinds) == 1, (op, form)
        loads, stores = kinds.pop()
        access[op, form] = (" | ".join((["RCG_LOAD"] if loads else []) +
                                       (["RCG_STORE"] if stores else []))
                            or "0")
        p(f"static const RCGGadget rcg_{op}_{form}[{len(entries)}] = {{")
        for i, spec in enumerate(entries):
            if spec:
                words = ", ".join(f"RCG_W_{w.upper()}" for w in spec.words)
                p(f"    [{i}] = {{ rcg_gadget_{spec.name}, {{ {words} }} }},")
        p("};\n")

    p("static const RCGSlot rcg_slots[RCG_NB_OPS][RCG_NB_FORMS] = {")
    for (op, form), group in slots.items():
        nb_shapes = len(EA_SHAPES) if group[0].has_mem else 1
        p(f"    [RCG_OP_{op.upper()}][RCG_FORM_{form.upper()}] = "
          f"{{ rcg_{op}_{form}, {nb_shapes}, {access[op, form]} }},")
    p("};\n")

    p("static const RCGFacts rcg_facts[RCG_NB_OPS] = {")
    for name in OP_NAMES:
        spec = next(s for s in all_specs if op_name(s) == name)
        if spec.kind == "alu":
            flags = [f"CC_OP_{spec.op.cc}B", True,
                     "RCG_SRCT_SUM" if spec.op.cc == "SUB" else "RCG_SRCT_NONE"]
        elif spec.kind == "zero":
            flags = ["CC_OP_EFLAGS", False, "RCG_SRCT_NONE"]
        elif spec.kind == "unary" and spec.op.cc:
            flags = [f"CC_OP_{spec.op.cc}B", True,
                     "RCG_SRCT_NONE" if spec.op.keeps_cf else "RCG_SRCT_ZERO"]
        elif spec.kind == "shift" and spec.op.cc:
            flags = [f"CC_OP_{spec.op.cc}B", True, "RCG_SRCT_NONE"]
        else:
            flags = [-1, False, "RCG_SRCT_NONE"]
        flags += ["cc_dst" in spec.cc_writes, "cc_src" in spec.cc_writes,
                  spec.kind == "unary" and spec.op.keeps_cf]
        facts = [f"RCG_KIND_{spec.kind.upper()}",
                 spec.kind in ("push", "pop", "call", "ret"),
                 spec.kind in ("call", "jmp", "ret"),
                 MO[spec.op.src] if spec.kind == "extend" else -1,
                 spec.reads_d] + flags
        fields = ("kind", "stack", "branch", "src_ot", "reads_d", "cc_op",
                  "by_width", "srcT", "dst", "src", "cf")
        p(f"    [RCG_OP_{name.upper()}] = {{")
        for k, f in zip(fields, facts):
            p(f"        .{k} = " +
              (str(f).lower() if isinstance(f, bool) else str(f)) + ",")
        p("    },")
    p("};")


#
# The tests: x86-64 code for each form, run over awkward values.
#


def test_layout():
    """ The fixed guest-physical addresses the tests' data lives at, as
    rcg-test.h defines them for the C side. """
    path = os.path.join(SRC, "tests", "tcg", "x86_64", "system", "rcg-test.h")
    layout = {}
    with open(path) as f:
        for line in f:
            m = re.match(r"#define (RCG_\w+)\s+(0x[0-9a-f]+)$", line.strip())
            if m:
                layout[m.group(1)] = int(m.group(2), 16)
    return layout


LAYOUT = test_layout()
RCG_MEM = LAYOUT["RCG_MEM"]
RCG_STACK = LAYOUT["RCG_STACK"]
RCG_FS_BASE = LAYOUT["RCG_FS_BASE"]
RCG_GS_BASE = LAYOUT["RCG_GS_BASE"]
RCG_HI = LAYOUT["RCG_HI"]
RCG_TARGET_MEM = LAYOUT["RCG_TARGET_MEM"]
RCG_TARGET_STACK = LAYOUT["RCG_TARGET_STACK"]


def hi(addr):
    """ The address above 4 GiB that rcg-test.h maps to the same memory as
    addr, which is in RCG_MEM's 2 MiB. """
    return addr - RCG_MEM + RCG_HI


# Where a memory operand is: 16 bytes into RCG_MEM, so that what a form
# should leave alone around it is checked too. Most operands reach it
# through its alias above 4 GiB, so that an address computed in 32 bits
# lands elsewhere; an absolute address (shape "d"), a RIP-relative one and
# one with the 32-bit address size reach OPERAND_LO itself.
OPERAND_LO = RCG_MEM + 16
OPERAND = hi(OPERAND_LO)

# Misaligned memory operands on the same page: one inside a 16-byte
# granule, and one across a granule's end, which an ordered access (LDAPR or
# STLR) must leave to the slow path.
MISALIGNED = (OPERAND + 1, OPERAND + 15)

# Where RSP starts, through the alias too, and misaligned stacks for PUSH
# and POP: each puts one of them inside a 16-byte granule and the other
# across a granule's end.
STACK = hi(RCG_STACK)
MISALIGNED_STACKS = (STACK + 4, STACK - 4)

# The segment overrides the cases use: none, FS and GS.
SEGS = (None, "fs", "gs")

# The index register's value where there is one: negative, so that the
# address computation must wrap.
INDEX = -2

# Base values for LEA, most of whose sums carry out of 16 or 32 bits, which
# the narrower operand sizes drop.
LEA_BASES = (0xfff8, 0x1fffffff8, 0xfffffffffffffff8, 0x0123456789abcdef)

# A base for [ebx+8] that reaches OPERAND_LO only with the 32-bit address
# size, which keeps the low 32 bits of the sum. A translator that took the
# 64-bit address would fault.
ADDR32_BASE = 0xffffffff00000000 | (OPERAND_LO - 8)

# Immediates for each width, as the encoding takes them: imm8 (sign-
# extended), the full immediate, and the edges between them.
IMMS = {
    8:  (0, 1, -1, 0x7f, -0x80),
    16: (0, 1, -1, 0x7f, -0x80, 0x7fff, -0x8000, 0x1234),
    32: (0, 1, -1, 0x7f, -0x80, 0x12345678, 0x7fffffff, -0x80000000),
    64: (0, 1, -1, 0x7f, -0x80, 0x12345678, 0x7fffffff, -0x80000000),
}
# MOV of a 64-bit register takes a full 64-bit immediate too.
MOV_IMMS64 = IMMS[64] + (0x123456789abcdef0, -0x8000000000000000)


class Case:
    """ One test case: an instruction, and the roles of its registers. a
    and b are the registers that take the values tested (b may be the
    memory operand instead, mem), and base and index those that make its
    address. operand is the memory operand's address, and rsp the stack
    pointer the case starts with. moved is the register rcg-faults moves
    across a page boundary: the base, or RSP for an access to the stack.
    writes says that the access it moves writes memory. target, for a
    branch in rcg-faults, is where it finds the address to go to: a
    register, RCG_TARGET_MEM (its memory operand) or RCG_TARGET_STACK (the
    top of the stack); the address is that of the end of the instruction.
    """

    def __init__(self, insn, width, a=-1, b=-1, mem=False, base=-1,
                 index=-1, base_value=0, index_value=0, stack=False,
                 writes=False, operand=OPERAND, rsp=STACK, moved=-1,
                 target=-1):
        self.insn = insn
        self.width = width
        self.a = a
        self.b = b
        self.mem = mem
        self.base = base
        self.index = index
        self.base_value = base_value
        self.index_value = index_value
        self.stack = stack
        self.writes = writes
        self.operand = operand
        self.rsp = rsp
        self.moved = moved
        self.target = target


def memory_operand(width, shape, seg, base=3, index=1, target=None):
    """ The x86 operand of shape at target (by default OPERAND, or
    OPERAND_LO for shape "d", whose 32-bit displacement cannot reach above
    4 GiB), with the segment override seg (None, "fs" or "gs"), and how to
    set its registers up: (text, base, index, base value, index value). """
    if target is None:
        target = OPERAND_LO if shape == "d" else OPERAND
    disp = 8
    seg_base = {None: 0, "fs": RCG_FS_BASE, "gs": RCG_GS_BASE}[seg]
    prefix = f"{seg}:" if seg else ""
    at = target - seg_base
    ptr = f"{PTR[width]} ptr " if width else ""
    if shape == "b":
        return (f"{ptr}{prefix}[{REGS64[base]}+{disp}]", base, -1,
                at - disp, 0)
    if shape.startswith("bi"):
        scale = int(shape[2])
        text = f"[{REGS64[base]}+{REGS64[index]}*{1 << scale}+{disp}]"
        return (f"{ptr}{prefix}{text}", base, index,
                at - (INDEX << scale) - disp, INDEX)
    if shape.startswith("i"):
        # The index holds all of the address but the displacement.
        scale = int(shape[1])
        index_value = (at - disp) >> scale
        disp = at - (index_value << scale)
        return (f"{ptr}{prefix}[{REGS64[index]}*{1 << scale}+{disp:#x}]",
                -1, index, 0, index_value)
    return (f"{ptr}{prefix}[{at:#x}]", -1, -1, 0, 0)


def rip_relative(width):
    """ A RIP-relative memory operand at OPERAND_LO. """
    return f"{PTR[width]} ptr [rip+rcg_mem+{OPERAND_LO - RCG_MEM}]"


def insn_cases():
    """ The cases of rcg-insns: every form the tables have a gadget for,
    and the neighbors of each that have none, which are left to TCG. """
    for op in ALU_OPS:
        for width in WIDTHS:
            yield from alu_cases(op, width)
    for width in WIDTHS:
        for n in (0, 8):
            r = reg_name(n, width)
            yield Case(f"xor {r}, {r}", width, a=n)
    # A high-byte register, left to TCG.
    yield Case("xor ah, ah", 8, a=0)
    for width in WIDTHS:
        yield from mov_cases(width)
    for width in LEA_WIDTHS:
        yield from lea_cases(width)
    yield from stack_cases()
    for op in EXTEND_OPS:
        for width in op.widths:
            yield from extend_cases(op, width)
    for op in UNARY_OPS:
        for width in WIDTHS:
            yield from unary_cases(op, width)
    for op in SHIFT_OPS:
        for width in WIDTHS:
            yield from shift_cases(op, width)
    for width in WIDTHS:
        yield from rotate_cases(width)
    yield from cond_cases()
    yield from branch_cases()
    yield from chain_cases()


def chain_cases():
    """ Gadgets after a TCG op in the same TB: one that writes a register
    the gadget keeps part of, reads or overwrites, and one that sets the
    flags the gadget sets again. Where the gadget overwrites a value, TCG
    may drop the op that made it. """
    for use in ("mov al, bl", "add ax, bx", "movzx ax, bl", "lea ax, [rbx+1]",
                "setz al", "cmovz rax, rbx", "cmovnz eax, ebx", "add rax, rbx",
                "mov eax, ebx", "mov rax, rbx", "xor eax, eax", "pop rax"):
        yield Case(f"bswap rax; {use}", 64, a=0, b=3,
                   stack=use.startswith("pop"))
    for setter in ("ror eax, 5", "rol rax, 3", "shl rax, cl", "imul rax, rbx",
                   "bswap rax"):
        for use in ("add rax, rbx", "cmp rbx, rax", "xor ebx, ebx",
                    "sub ebx, eax; setb cl"):
            yield Case(f"{setter}; {use}", 64, a=0, b=3)


def reg_pairs(width):
    """ Register pairs for two-register forms: two low ones, one twice, two
    that need REX, and at 8 bits the REX-only and high-byte registers. """
    pairs = [(reg_name(0, width), 0, reg_name(3, width), 3),
             (reg_name(1, width), 1, reg_name(1, width), 1),
             (reg_name(8, width), 8, reg_name(15, width), 15)]
    if width == 8:
        pairs += [("sil", 6, "dil", 7), ("ah", 0, "bl", 3), ("bl", 3, "ch", 1)]
    return pairs


def memory_cases(name, width, forms, writes):
    """ The cases of an instruction's rm and mr forms (those of forms), for
    every operand shape and segment override, then on the same page but
    misaligned, then with the 32-bit address size, which is left to TCG.
    writes says that the mr form writes its memory operand. """
    def both(text, **kw):
        if "rm" in forms:
            yield Case(f"{name} {reg_name(0, width)}, {text}", width, a=0,
                       mem=True, **kw)
        if "mr" in forms:
            yield Case(f"{name} {text}, {reg_name(2, width)}", width, a=2,
                       mem=True, writes=writes, **kw)

    for shape in EA_SHAPES:
        for seg in SEGS:
            text, base, index, bv, iv = memory_operand(width, shape, seg)
            yield from both(text, base=base, index=index, base_value=bv,
                            index_value=iv)
    if width > 8:
        for target in MISALIGNED:
            text, base, _, bv, _ = memory_operand(width, "b", None,
                                                  target=target)
            yield from both(text, base=base, base_value=bv, operand=target)
    if width >= 32:
        yield from both(f"{PTR[width]} ptr [ebx+8]", base=3,
                        base_value=ADDR32_BASE)


def mi_cases(name, width, writes):
    """ The cases of an mi form for every operand shape and segment
    override but [rbx+8] without one, where the callers try every
    immediate. """
    for shape in EA_SHAPES:
        for seg in SEGS:
            if shape == "b" and seg is None:
                continue
            text, base, index, bv, iv = memory_operand(width, shape, seg)
            yield Case(f"{name} {text}, {-0x80}", width, mem=True, base=base,
                       index=index, base_value=bv, index_value=iv,
                       writes=writes)


def alu_cases(op, width):
    two_ways = op.name != "test"
    for ra, a, rb, b in reg_pairs(width):
        # Both encodings of a register-to-register form, where there are two.
        for pseudo in (("{load} ", "{store} ") if two_ways else ("",)):
            yield Case(f"{pseudo}{op.name} {ra}, {rb}", width, a=a,
                       b=b if b != a else -1)
    yield from memory_cases(op.name, width, op.forms, op.writes)
    text, base, _, bv, _ = memory_operand(width, "b", None)
    if "mi" in op.forms:
        for imm in IMMS[width]:
            yield Case(f"{op.name} {text}, {imm}", width, mem=True,
                       base=base, base_value=bv, writes=op.writes)
        yield from mi_cases(op.name, width, op.writes)
    # The base register as the other operand too.
    if "rm" in op.forms:
        yield Case(f"{op.name} {reg_name(3, width)}, {text}", width, mem=True,
                   base=base, base_value=bv)
    yield Case(f"{op.name} {text}, {reg_name(3, width)}", width, mem=True,
               base=base, base_value=bv, writes=op.writes)
    yield Case(f"{op.name} {rip_relative(width)}, {reg_name(2, width)}", width,
               a=2, mem=True, writes=op.writes)
    for n in (0, 1, 9):
        for imm in IMMS[width]:
            yield Case(f"{op.name} {reg_name(n, width)}, {imm}", width, a=n)
    if width == 8:
        for imm in IMMS[8]:
            yield Case(f"{op.name} ah, {imm}", width, a=0)


def mov_cases(width):
    for ra, a, rb, b in reg_pairs(width):
        for pseudo in ("{load} ", "{store} "):
            yield Case(f"{pseudo}mov {ra}, {rb}", width, a=a,
                       b=b if b != a else -1)
    yield from memory_cases("mov", width, ("rm", "mr"), True)
    text, base, _, bv, _ = memory_operand(width, "b", None)
    yield Case(f"mov {reg_name(3, width)}, {text}", width, mem=True,
               base=base, base_value=bv)
    yield Case(f"mov {rip_relative(width)}, {reg_name(2, width)}", width,
               a=2, mem=True, writes=True)
    for imm in (IMMS[width] if width < 64 else MOV_IMMS64):
        for n in (0, 9):
            if -2**31 <= imm < 2**31:
                yield Case(f"mov {reg_name(n, width)}, {imm}", width, a=n)
            else:
                imm64 = imm & (2**64 - 1)
                yield Case(f"movabs {reg_name(n, width)}, {imm64:#x}",
                           width, a=n)
        if -2**31 <= imm < 2**31:
            yield Case(f"mov {text}, {imm}", width, mem=True, base=base,
                       base_value=bv, writes=True)
    yield from mi_cases("mov", width, True)
    if width == 8:
        yield Case("mov ah, bl", 8, a=0, b=3)
        yield Case("mov bl, ah", 8, a=3, b=0)


def lea_cases(width):
    r = reg_name(0, width)
    for shape in EA_SHAPES:
        text, base, index, bv, iv = memory_operand(None, shape, None)
        yield Case(f"lea {r}, {text}", width, base=base, index=index,
                   base_value=bv, index_value=iv)
    yield Case(f"lea {r}, [rip+rcg_mem+{OPERAND_LO - RCG_MEM}]", width)
    for bv in LEA_BASES:
        yield Case(f"lea {r}, [rbx+8]", width, base=3, base_value=bv)
        yield Case(f"lea {r}, [rbx+rcx*2+8]", width, base=3, index=1,
                   base_value=bv, index_value=INDEX)
    # An FS override, which LEA ignores, then the 32-bit address size,
    # which is left to TCG. The assembler warns of an override on LEA, so it
    # is written as its prefix byte.
    yield Case(f".byte 0x64; lea {r}, [rbx+8]", width, base=3,
               base_value=OPERAND - 8)
    yield Case(f"lea {r}, [ebx+8]", width, base=3, base_value=ADDR32_BASE)


def extend_cases(op, width):
    mnemonic = "movsxd" if op.name == "movsxd" else op.name[:5]
    pairs = [(0, 3), (1, 1), (8, 15)]
    if op.src == 8:
        pairs += [(6, 7)]
    for a, b in pairs:
        yield Case(f"{mnemonic} {reg_name(a, width)}, {reg_name(b, op.src)}",
                   width, a=a, b=b if b != a else -1)
    if op.src == 8 and width < 64:
        # AH as the source is TCG's (and cannot go with REX.W).
        yield Case(f"{mnemonic} {reg_name(3, width)}, ah", width, a=3, b=0)
    for shape in EA_SHAPES:
        for seg in SEGS:
            text, base, index, bv, iv = memory_operand(op.src, shape, seg)
            yield Case(f"{mnemonic} {reg_name(0, width)}, {text}", width, a=0,
                       mem=True, base=base, index=index, base_value=bv,
                       index_value=iv)
    if op.src > 8:
        for target in MISALIGNED:
            text, base, _, bv, _ = memory_operand(op.src, "b", None,
                                                  target=target)
            yield Case(f"{mnemonic} {reg_name(0, width)}, {text}", width,
                       a=0, mem=True, base=base, base_value=bv,
                       operand=target)
    yield Case(f"{mnemonic} {reg_name(2, width)}, {rip_relative(op.src)}",
               width, a=2, mem=True)


def unary_cases(op, width):
    for n in (0, 9):
        yield Case(f"{op.name} {reg_name(n, width)}", width, a=n)
    if width == 8:
        yield Case(f"{op.name} sil", 8, a=6)
        yield Case(f"{op.name} ah", 8, a=0)
    for shape in EA_SHAPES:
        for seg in SEGS:
            text, base, index, bv, iv = memory_operand(width, shape, seg)
            yield Case(f"{op.name} {text}", width, mem=True, base=base,
                       index=index, base_value=bv, index_value=iv,
                       writes=True)
    if width > 8:
        for target in MISALIGNED:
            text, base, _, bv, _ = memory_operand(width, "b", None,
                                                  target=target)
            yield Case(f"{op.name} {text}", width, mem=True, base=base,
                       base_value=bv, operand=target, writes=True)
    yield Case(f"{op.name} {rip_relative(width)}", width, mem=True,
               writes=True)


# Shift counts: as the encoding takes them, before the mask (0x1f, or 0x3f
# at 64 bits); those that mask to 0 are TCG's.
SHIFT_COUNTS = (1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255)


def shift_cases(op, width):
    for n in (0, 9):
        for count in SHIFT_COUNTS:
            yield Case(f"{op.name} {reg_name(n, width)}, {count}", width, a=n)
        # By CL: TCG's.
        yield Case(f"{op.name} {reg_name(n, width)}, cl", width, a=n)
    if width == 8:
        yield Case(f"{op.name} ah, 3", 8, a=0)
    for shape in EA_SHAPES:
        for seg in SEGS:
            text, base, index, bv, iv = memory_operand(width, shape, seg)
            for count in ((1, 5) if shape == "b" and not seg else (3,)):
                yield Case(f"{op.name} {text}, {count}", width, mem=True,
                           base=base, index=index, base_value=bv,
                           index_value=iv, writes=True)
    if width > 8:
        for target in MISALIGNED:
            text, base, _, bv, _ = memory_operand(width, "b", None,
                                                  target=target)
            yield Case(f"{op.name} {text}, 1", width, mem=True, base=base,
                       base_value=bv, operand=target, writes=True)
    yield Case(f"{op.name} {rip_relative(width)}, 1", width, mem=True,
               writes=True)


def flag_setters(width):
    """ Instructions that leave each lazy-flags state the condition gadgets
    read but CC_OP_EFLAGS, on RAX and RBX at width. """
    ra, rb = reg_name(0, width), reg_name(3, width)
    return {
        "sub": [f"cmp {ra}, {rb}", f"sub {ra}, {rb}", f"neg {ra}"],
        "add": [f"add {ra}, {rb}"],
        "logic": [f"test {ra}, {rb}", f"and {ra}, {rb}"],
        "inc": [f"inc {ra}"],
        "dec": [f"dec {ra}"],
    }


# AH for SAHF: CF, PF, AF, ZF and SF apart, two together, and all, so that
# a condition that reads the wrong flag shows.
SAHF_PATTERNS = (0x00, 0x01, 0x04, 0x10, 0x40, 0x80, 0x41, 0xd5)


def cond_cases():
    """ Each condition after each lazy-flags state, read by Jcc (which
    leaves its outcome in RCX), SETcc and CMOVcc: the first instruction
    leaves the state, and the second, in the same TB, reads it. """
    def consumers(cond, width):
        cc = CONDS[cond]
        yield f"j{cc} 1f; mov ecx, 1; 1:"
        yield f"set{cc} cl"
        for cmov_width in CMOV_WIDTHS:
            yield (f"cmov{cc} {reg_name(1, cmov_width)}, "
                   f"{reg_name(2, cmov_width)}")

    for width in WIDTHS:
        for cls, setters in flag_setters(width).items():
            for setter in setters:
                for cond in range(16):
                    for use in consumers(cond, width):
                        yield Case(f"{setter}; {use}", width, a=0, b=3)
    # CC_OP_EFLAGS, from SAHF.
    for pattern in SAHF_PATTERNS:
        for cond in range(16):
            for use in consumers(cond, 64):
                yield Case(f"mov ah, {pattern:#x}; sahf; {use}", 64)
    # Jcc alone, reading the start's state: after POPF it is from before the
    # TB, which is TCG's; after the start's CMP it is in the same TB.
    for cond in (2, 12):
        yield Case(f"j{CONDS[cond]} 1f; mov ecx, 1; 1:", 64)


def stack_cases():
    for n in (0, 12):
        yield Case(f"push {REGS64[n]}", 64, a=n, stack=True)
        yield Case(f"pop {REGS64[n]}", 64, a=n, stack=True)
    yield Case("push rsp", 64, stack=True)
    yield Case("pop rsp", 64, stack=True)
    for rsp in MISALIGNED_STACKS:
        yield Case("push rax", 64, a=0, stack=True, rsp=rsp)
        yield Case("pop rax", 64, a=0, stack=True, rsp=rsp)
    for imm in (0, 1, -1, 0x7f, -0x80, 0x12345678, -0x80000000):
        yield Case(f"push {imm}", 64, stack=True)
    for shape in EA_SHAPES:
        for seg in SEGS:
            text, base, index, bv, iv = memory_operand(64, shape, seg)
            yield Case(f"push {text}", 64, mem=True, base=base, index=index,
                       base_value=bv, index_value=iv, stack=True)
    # Left to TCG: 16-bit pushes and pops, and POP to memory, whose address
    # uses RSP after the pop. PUSH from [rsp+8] is RCG's: its address uses
    # RSP before the push, as TCG's does.
    yield Case("push ax", 16, a=0, stack=True)
    yield Case("pop ax", 16, a=0, stack=True)
    yield Case("push qword ptr [rsp+8]", 64, stack=True)
    yield Case("pop qword ptr [rsp+8]", 64, stack=True)
    # ENTER, whose frame size is unsigned, at level 0: a deeper level would
    # copy frame pointers from RBP, which holds no address here.
    yield Case("enter 8, 0", 64, stack=True)
    yield Case("enter 0x8000, 0", 64, stack=True)


def branch_cases():
    """ CALL, JMP and RET. Each goes to label 2, past a UD2 at label 1,
    which a branch not taken would run, and a CALL's return address is
    label 1, so that a CALL that pushed its target shows. What they leave
    that depends on where the test is (return addresses, targets) is made
    relative to label 1, or cleared, before the case ends. """
    clear = "mov qword ptr [rsp-8], 0"
    back = "2: pop rsi; lea rdi, [rip+1b]; sub rsi, rdi; mov edi, 0"
    yield Case(f"call 2f; 1: ud2; {back}; {clear}", 64, stack=True)
    yield Case(f"lea rdx, [rip+2f]; call rdx; 1: ud2; {back}; mov edx, 0; "
               f"{clear}", 64, stack=True)
    yield Case("lea rdx, [rip+2f]; jmp rdx; 1: ud2; 2: mov edx, 0", 64)
    targets = [memory_operand(64, shape, seg)
               for shape in EA_SHAPES for seg in SEGS]
    targets.append((rip_relative(64), -1, -1, 0, 0))
    for text, base, index, bv, iv in targets:
        set_target = f"lea rdx, [rip+2f]; mov {text}, rdx"
        done = f"mov edx, 0; mov {text}, 0"
        yield Case(f"{set_target}; call {text}; 1: ud2; {back}; {done}; "
                   f"{clear}", 64, mem=True, base=base, index=index,
                   base_value=bv, index_value=iv, stack=True)
        yield Case(f"{set_target}; jmp {text}; 1: ud2; 2: {done}", 64,
                   mem=True, base=base, index=index, base_value=bv,
                   index_value=iv)
    # RET's count is unsigned: 0x8000 and 0xfff8 free 32 KiB and 64 KiB.
    for adjust in (None, 0, 8, 16, 0x8000, 0xfff8):
        ret = "ret" if adjust is None else f"ret {adjust}"
        yield Case(f"lea rsi, [rip+2f]; push rsi; {ret}; 1: ud2; "
                   f"2: mov esi, 0; mov qword ptr [rsp-{8 + (adjust or 0)}], 0",
                   64, stack=True)


def fault_cases():
    """ The cases of rcg-faults: each memory form at each width, with the
    memory operand at an address from the base register (RBX) alone, which
    the test moves across a page boundary, then the stack's accesses, for
    which it moves RSP. A branch goes to the end of the instruction. """
    def mem(insn, width, **kw):
        return Case(insn, width, mem=True, base=3, moved=3, **kw)

    for op in ALU_OPS:
        for width in WIDTHS:
            m = f"{PTR[width]} ptr [rbx]"
            if "rm" in op.forms:
                yield mem(f"{op.name} {reg_name(0, width)}, {m}", width, a=0)
            yield mem(f"{op.name} {m}, {reg_name(2, width)}", width, a=2,
                      writes=op.writes)
            yield mem(f"{op.name} {m}, 0x55", width, writes=op.writes)
    for width in WIDTHS:
        m = f"{PTR[width]} ptr [rbx]"
        yield mem(f"mov {reg_name(0, width)}, {m}", width, a=0)
        yield mem(f"mov {m}, {reg_name(2, width)}", width, a=2, writes=True)
        yield mem(f"mov {m}, 0x55", width, writes=True)
    for op in EXTEND_OPS:
        for width in op.widths:
            # The case's width is the access's, the source's here.
            mnemonic = "movsxd" if op.name == "movsxd" else op.name[:5]
            yield mem(f"{mnemonic} {reg_name(0, width)}, "
                      f"{PTR[op.src]} ptr [rbx]", op.src, a=0)
    for op in UNARY_OPS:
        for width in WIDTHS:
            yield mem(f"{op.name} {PTR[width]} ptr [rbx]", width, writes=True)
    for op in SHIFT_OPS:
        for width in WIDTHS:
            for count in (1, 3):
                yield mem(f"{op.name} {PTR[width]} ptr [rbx], {count}", width,
                          writes=True)
    yield mem("push qword ptr [rbx]", 64, stack=True)
    yield mem("call qword ptr [rbx]", 64, stack=True, target=RCG_TARGET_MEM)
    yield mem("jmp qword ptr [rbx]", 64, target=RCG_TARGET_MEM)

    def stack(insn, **kw):
        return Case(insn, 64, stack=True, moved=R_ESP, **kw)

    yield stack("push rax", a=0, writes=True)
    yield stack("push 0x55", writes=True)
    yield stack("pop rax", a=0)
    yield stack("call 1f; 1:", writes=True)
    yield stack("call rdx", writes=True, target=2)
    yield stack("ret", target=RCG_TARGET_STACK)
    yield stack("ret 8", target=RCG_TARGET_STACK)
    # Memory operands whose load succeeds and whose store to the stack
    # faults.
    yield stack("push qword ptr [rbx]", mem=True, base=3, base_value=OPERAND,
                writes=True)
    yield stack("call qword ptr [rbx]", mem=True, base=3, base_value=OPERAND,
                writes=True, target=RCG_TARGET_MEM)


def rotate_cases(width):
    """ ROL and ROR by each count, and the flags they leave, after each
    lazy-flags state and as a condition reads them. Only the register forms
    at 32 and 64 bits by an immediate have a gadget (ROR's, which ROL uses
    too); the rest are TCG's. """
    reg = reg_name(0, width)
    text, base, _, bv, _ = memory_operand(width, "b", None)
    for name in ("rol", "ror"):
        for n in (0, 9):
            for count in SHIFT_COUNTS:
                yield Case(f"{name} {reg_name(n, width)}, {count}", width,
                           a=n)
        yield Case(f"{name} {reg}, cl", width, a=0)
        yield Case(f"{name} {text}, 3", width, mem=True, base=base,
                   base_value=bv, writes=True)
        if width not in ROTATE_WIDTHS:
            continue
        for setters in flag_setters(width).values():
            yield Case(f"{setters[0]}; {name} {reg}, 5", width, a=0, b=3)
        for cond in range(16):
            yield Case(f"{name} {reg}, 1; j{CONDS[cond]} 1f; mov ecx, 1; 1:",
                       width, a=0)


def write_cases(cases, out, prefix):
    """ The cases as rcg-test.h's RCG_CASE() macros, one per case, which
    make the functions that run the instruction, then a table of the
    cases. """
    cases = list(cases)
    print("/* Automatically generated by rcg-gen.py. Do not edit. */\n",
          file=out)
    for i, c in enumerate(cases):
        print(f'RCG_CASE({prefix}{i}, "{c.insn}")', file=out)
    print(f"\nstatic const struct rcg_case {prefix}cases[] = {{", file=out)
    for i, c in enumerate(cases):
        name = f"{prefix}{i}"
        print(f'    {{ "{c.insn}", {name}, {name}_insn, {name}_end, '
              f'{name}_sub, {name}_sub_insn, {name}_sub_end, {c.width}, '
              f'{c.a}, {c.b}, {int(c.mem)}, {c.base}, {c.index}, '
              f'{c.base_value:#x}, {c.index_value}, {int(c.stack)}, '
              f'{int(c.writes)}, {c.operand:#x}, {c.rsp:#x}, {c.moved}, '
              f'{c.target} }},', file=out)
    print("};", file=out)


def check_coverage(order, nm, traces):
    """ Checks that the rcg_insn trace events in traces, from runs of
    QEMU's x86_64 system emulator, took every gadget the translator can
    pick under order: "ordered" where tcg_ldst_ordered() holds, which
    picks the ordered twins, else "plain". nm is nm's listing of that
    QEMU, from which each trace's ASLR slide is found. Returns whether
    every gadget ran. """
    names = {}
    for line in open(nm):
        parts = line.split()
        if len(parts) == 3 and parts[2].lstrip("_").startswith("rcg_gadget_"):
            names[int(parts[0], 16)] = parts[2].lstrip("_")[11:]
    taken = set()
    for path in traces:
        seen = set()
        for line in open(path):
            m = re.search(r"rcg_insn pc 0x[0-9a-f]+ gadget (0x[0-9a-f]+)",
                          line)
            if m:
                seen.add(int(m.group(1), 16))
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

    want = {spec.name for spec in list(specs()) + list(cond_specs())
            if spec.ordered == (order == "ordered") or
            not getattr(spec, "accesses_memory", False)}
    missed = sorted(want - taken)
    for name in missed:
        print(f"never taken: rcg_gadget_{name}", file=sys.stderr)
    print(f"RCG: {len(want) - len(missed)} of {len(want)} {order} gadgets "
          f"taken", file=sys.stderr)
    return not missed


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--insn-tests", metavar="FILE",
                        help="write rcg-insns.c's cases to FILE")
    parser.add_argument("--fault-tests", metavar="FILE",
                        help="write rcg-faults.c's cases to FILE")
    parser.add_argument("--check", action="store_true",
                        help="render every gadget's body and check it")
    parser.add_argument("--gadgets", metavar="DIR",
                        help="write the gadgets for TCTI and their table "
                             "to DIR")
    parser.add_argument("--coverage", nargs="+", metavar="ARG",
                        help="ORDER NM TRACE...: check that the traces "
                             "took every gadget for ORDER (ordered or "
                             "plain)")
    args = parser.parse_args()
    if not (args.insn_tests or args.fault_tests or args.check or
            args.gadgets or args.coverage):
        parser.error("nothing to do")
    if args.coverage and (len(args.coverage) < 3 or
                          args.coverage[0] not in ("ordered", "plain")):
        parser.error("--coverage takes ordered|plain NM TRACE...")

    if args.check:
        check()
    if args.gadgets:
        write_gadgets(args.gadgets)
    if args.insn_tests:
        with open(args.insn_tests, "w") as out:
            write_cases(insn_cases(), out, "rcg_insn_")
    if args.fault_tests:
        with open(args.fault_tests, "w") as out:
            write_cases(fault_cases(), out, "rcg_fault_")
    if args.coverage:
        order, nm, *traces = args.coverage
        if not check_coverage(order, nm, traces):
            sys.exit(1)


if __name__ == "__main__":
    main()
