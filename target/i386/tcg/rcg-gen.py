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
--coverage checks that the tests took every gadget (see check_coverage()):

    rcg-gen.py --insn-tests FILE
    rcg-gen.py --jcc-tests FILE
    rcg-gen.py --fault-tests FILE
    rcg-gen.py --jcc-fault-tests FILE
    rcg-gen.py --check
    rcg-gen.py --gadgets DIR
    rcg-gen.py --coverage ordered|plain NM TRACE...

Only 64-bit code without LOCK is covered, and the 32-bit address size
only without a memory operand; anything else is left to TCG.
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
PTR = {8: "byte", 16: "word", 32: "dword", 64: "qword", 128: "xmmword"}
MO = {8: "MO_8", 16: "MO_16", 32: "MO_32", 64: "MO_64", 128: "MO_128"}


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


# The operand words that always fit in 32 bits, signed: env offsets, the
# MemOpIdx, the CPUTLBDescFast's offset and a CC_OP. disp and imm may not.
NARROW_WORDS = ("d", "s", "s1", "base", "index", "seg", "oi", "tlb", "ccop")


def stream_words(words):
    """ How a Spec's words go in the stream, which rcg_pack_words() must
    match: a list of stream words, each a tuple of the words it holds. A
    gadget that accesses memory, which is one with a tlb word, has its
    narrow words two to a stream word, the first in the low half, then an
    odd one out alone, then each of the others alone. Any other gadget has
    each word alone. A memory gadget splits the pairs while it waits for
    the TLB entry; packing the others only made them slower. """
    if "tlb" not in words:
        return [(w,) for w in words]
    narrow = [w for w in words if w in NARROW_WORDS]
    return ([tuple(narrow[i:i + 2]) for i in range(0, len(narrow), 2)] +
            [(w,) for w in words if w not in NARROW_WORDS])


#
# The tables: what there is a gadget for.
#

class VMov:
    """ A move of width bits between XMM registers and memory. At 128 bits,
    as gen_MOVDQ does: MOVDQA and MOVAPS (aligned, which a memory operand
    must be), and MOVDQU and MOVUPS. At 64 and 32 bits, the low lane, as
    MOVSD and MOVSS do: from memory, the rest of the register is cleared
    (gen_VMOVSD_ld, gen_VMOVSS_ld); between registers, it is kept
    (gen_VMOVLPx, gen_VMOVSS); to memory, only the lane is stored
    (gen_VMOVLPx_st, gen_VMOVSS_st). """

    def __init__(self, name, width, aligned=False):
        self.name = name
        self.width = width
        self.aligned = aligned


VMOV_OPS = (VMov("movdqa", 128, aligned=True), VMov("movdqu", 128),
            VMov("movsd", 64), VMov("movss", 32))


class VFp:
    """ An SSE floating-point op, dest = dest op src, or for SQRT (unary)
    dest = op src, with the helper gen_fp_sse() or gen_unary_fp_sse() picks
    by prefix: on every lane (ps and pd, lanes of 32 and 64 bits) or on the
    low lane, keeping the rest of the destination (ss and sd). a64 is the
    AArch64 instruction. """

    def __init__(self, base, a64, suffix, unary=False):
        self.name = base + suffix
        self.a64 = a64
        self.unary = unary
        self.lane = 32 if suffix[1] == "s" else 64
        self.packed = suffix[0] == "p"
        self.width = 128 if self.packed else self.lane
        self.helper = f"helper_{self.name}" + ("_xmm" if self.packed else "")

    @property
    def reads_d(self):
        """ Whether the destination is an input too: all but SQRT's packed
        forms, which write every lane from the source alone. """
        return not (self.unary and self.packed)


# Each op's four forms, in the order rcg_select() relies on when it adds
# the prefix's index to the ps op.
VFP_SUFFIXES = ("ps", "pd", "ss", "sd")
VFP_OPS = tuple(VFp(base, a64, suffix, unary=base == "sqrt")
                for base, a64 in (("add", "fadd"), ("sub", "fsub"),
                                  ("mul", "fmul"), ("div", "fdiv"),
                                  ("sqrt", "fsqrt"))
                for suffix in VFP_SUFFIXES)


class VLane:
    """ UNPCKLPS, UNPCKLPD, UNPCKHPS and UNPCKHPD: the low or high halves of
    the destination and the source, interleaved by lanes of 32 or 64 bits.
    TCG calls the punpckl and punpckh helpers for them, which give the same
    lanes. """

    def __init__(self, high, lane):
        self.name = f"unpck{'h' if high else 'l'}p{'s' if lane == 32 else 'd'}"
        self.high = high
        self.lane = lane
        self.width = 128


# In the order rcg_select() adds the prefix's index to: ps, then pd.
VLANE_OPS = tuple(VLane(high, lane) for high in (False, True)
                  for lane in (32, 64))


class Alu:
    """ A two-operand ALU instruction: dest = dest op src. The result is
    written back unless writes is false (CMP and TEST). cc is the lazy-flags
    state it leaves, as TCG's gen_<name> does: "ADD", "SUB", "LOGIC", "ADC"
    or "SBB", for CC_OP_<cc>B plus the width's MemOp.

    ADC and SBB also add or subtract CF. The translator puts CF in cc_src2
    before the gadget, and CC_OP_ADCB and CC_OP_SBBB keep it there. """

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
    Alu("adc",  "add", "ADC",   True,  ALU_FORMS),
    Alu("sbb",  "sub", "SBB",   True,  ALU_FORMS),
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
    gen_INC and gen_DEC put in cc_src: see Spec.cf. """

    def __init__(self, name, a64, cc):
        self.name = name
        self.a64 = a64
        self.cc = cc


UNARY_OPS = (
    Unary("not", "mvn {r}, {a}",     None),
    Unary("neg", "neg {r}, {a}",     "SUB"),
    Unary("inc", "add {r}, {a}, #1", "INC"),
    Unary("dec", "sub {r}, {a}, #1", "DEC"),
)


class Shift:
    """ SHL, SHR and SAR by an immediate count (or 1), or by CL: dest = dest
    shifted, on the value zero-extended (SAR: sign-extended) from the
    operand size as TCG's ZExtT0 and SExtT0 load it, with cc_dst the result
    and cc_src the value shifted by one less, as gen_SHL and friends leave
    them.

    An immediate count is a word, which the translator must mask, and a
    count that masks to 0 must be left to TCG: cc_src would be the value
    shifted by count - 1, that is by -1. The gadget masks a count in CL
    itself (forms rr and mr, CL being the source), and where it masks to 0
    it still writes the operand back but keeps the flags state, as
    gen_shift_dynamic_flags() does. Which happened is known only when it
    runs, so the gadget writes cc_op, and the translator must take the
    state as CC_OP_DYNAMIC after it. The translator gives the state before
    as the word ccop, which the gadget stores for a count of 0 unless it is
    CC_OP_DYNAMIC, when env already holds the state. """

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
# ROL as ROR by the width less the count. Its cc is None because the
# gadget leaves the flags state alone, not because the instruction does: the
# translator must have TCG compute the CF and OF the instruction leaves, by
# ROL's rule for a ROL (CF the result's bit 0) and ROR's for a ROR (CF its
# top bit), which TCG drops when nothing reads them. As for the shifts, a
# count that masks to 0 must be left to TCG.
ROTATE_OP = Shift("ror", "ror", None)
ROTATE_WIDTHS = (32, 64)


class Mul:
    """ MUL and IMUL with one operand: RAX times the source, both zero-
    (MUL) or sign-extended (IMUL) from the operand size, to AX at 8 bits,
    else to RDX:RAX at the operand size. With two or three operands (IMUL3,
    as decode-new names it), IMUL is dest = dest * src or dest = src * imm,
    signed, at 16, 32 or 64 bits. Each leaves CC_OP_MULB plus the width's
    MemOp, with cc_dst and cc_src as TCG's gen_MUL, gen_IMUL and gen_IMUL3
    leave them. """

    def __init__(self, name, signed):
        self.name = name
        self.signed = signed


MUL_OPS = (Mul("mul", False), Mul("imul", True))
IMUL3_OP = Mul("imul3", True)
IMUL3_FORMS = ("rr", "rm", "rri", "rmi")
IMUL3_WIDTHS = (16, 32, 64)


class BitTest:
    """ BT, BTS, BTR and BTC: CF = bit n of dest, n being the source (a
    register or an immediate) masked to the operand size; BTS, BTR and BTC
    then set, clear or flip that bit. a64 is the AArch64 instruction that
    does so, taking the mask 1 << n as its second operand. A register
    operand is read whole, as TCG reads it. With a register for n, a
    memory operand is a bit string that can reach beyond the operand, so
    that form is left to TCG.

    ZF is kept and the other flags are undefined, so the flags state TCG
    leaves depends on the one before (see gen_bt_flags()). After
    CC_OP_DYNAMIC or a state with EFLAGS in cc_src, TCG computes the flags
    in full, and the instruction is left to TCG. After any other state,
    the gadget writes cc_src as dest shifted right by n and keeps cc_dst,
    and the translator records CC_OP_SARB plus the earlier state's MemOp.
    """

    def __init__(self, name, a64):
        self.name = name
        self.a64 = a64

    @property
    def writes(self):
        return self.a64 is not None


BT_OPS = (BitTest("bt", None), BitTest("bts", "orr"), BitTest("btr", "bic"),
          BitTest("btc", "eor"))
BT_FORMS = ("rr", "ri", "mi")
BT_WIDTHS = (16, 32, 64)


# Moves among registers without flags, by decode-new's names: CBW (also
# CWDE and CDQE) sign-extends the low half of RAX at the operand size, CWD
# (also CDQ and CQO) fills RDX with the sign of RAX at the operand size, and
# XCHG swaps two registers (with memory it is locked, which is TCG's). These
# are their widths.
CBW_WIDTHS = (16, 32, 64)
XCHG_WIDTHS = WIDTHS


# The lazy-flags states a condition can be read from without a helper, as
# TCG's CC_OP_<class>B + the width's MemOp, or CC_OP_EFLAGS alone.
CC_CLASSES = ([(cls, width)
               for cls in ("sub", "add", "logic", "inc", "dec", "sar")
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
    CC_OP, then branches), "jccgoto" (the same, then the jump either way
    as TCTI's addi_env_goto_tb makes it), "setcc" (an 8-bit register) or
    "cmov" (register to register at width cmov_width). """

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
        if self.kind in ("jcc", "jccgoto"):
            return ["ccop"]
        if self.kind == "setcc":
            return ["d"]
        return ["d", "s"]

    @property
    def stream(self):
        """ The words, each alone in a stream word: rcg_translate_cond()
        never packs them. """
        return [(w,) for w in self.words]


def cond_specs():
    """ Every condition gadget there is: P and NP only from CC_OP_EFLAGS. """
    for cls, width in CC_CLASSES:
        for cond in range(16):
            if cond >> 1 == 5 and cls != "eflags":
                continue
            yield CondSpec("jcc", cls, width, cond)
            yield CondSpec("jccgoto", cls, width, cond)
            yield CondSpec("setcc", cls, width, cond)
            for cmov_width in CMOV_WIDTHS:
                yield CondSpec("cmov", cls, width, cond, cmov_width)


class FusedSpec:
    """ A CMP or TEST (fused_setters()) and the Jcc right after it, in one
    gadget: kind "fjcc" (as "jcc") or "fjccgoto" (as "jccgoto"). setter is
    the CMP's or TEST's Spec, and cond the Jcc's condition. The gadget does
    the setter's work, then the Jcc's with the condition worked out from
    the registers the setter compared, rather than from cc_dst and cc_src
    reloaded from env. Its words are the setter's, then the Jcc's. A memory
    setter's gadget may fault in its load, before it writes anything. """

    def __init__(self, kind, setter, cond):
        self.kind = kind
        self.setter = setter
        self.cond = cond
        self.cls = "sub" if setter.op.cc == "SUB" else "logic"
        self.has_mem = setter.has_mem
        self.shape = setter.shape
        self.seg = setter.seg
        self.ordered = setter.ordered

    @property
    def name(self):
        return f"{self.kind}_{self.setter.name}_{CONDS[self.cond]}"

    @property
    def accesses_memory(self):
        return self.setter.accesses_memory

    @property
    def words(self):
        return [*self.setter.words, "ccop"]

    @property
    def stream(self):
        """ The setter's stream words, then the Jcc's word alone:
        tcg_gen_rich_br_join() appends it to the setter's packed words. Not
        stream_words(self.words), which would pair it with the setter's. """
        return [*self.setter.stream, ("ccop",)]


# The widths of the fused gadgets' memory forms: 16 bits is rare there.
FUSED_MEMORY_WIDTHS = (8, 32, 64)


def fused_setters():
    """ The setters a Jcc right after them can join, in rcg_fused_setter's
    order: CMP and TEST of two registers, of a register and an immediate,
    and with memory at shape b with no segment base. Nearly all memory CMPs
    and TESTs use shape b. """
    for op in ALU_OPS:
        if op.name in ("cmp", "test"):
            for form in ("rr", "ri"):
                for width in WIDTHS:
                    yield Spec("alu", op, form, width)
    for op in ALU_OPS:
        if op.name in ("cmp", "test"):
            for form in op.forms:
                if "m" in form:
                    for width in FUSED_MEMORY_WIDTHS:
                        for ordered in (False, True):
                            yield Spec("alu", op, form, width, "b", False,
                                       ordered)


def fused_specs():
    """ Every fused gadget: all conditions but P and NP, which are read only
    from CC_OP_EFLAGS, a state no setter here leaves. """
    for setter in fused_setters():
        for cond in range(16):
            if cond >> 1 != 5:
                yield FusedSpec("fjcc", setter, cond)
                yield FusedSpec("fjccgoto", setter, cond)


class Spec:
    """ One gadget: what it does and the words it takes.

    kind is "alu", "zero" (XOR of a register with itself), "mov", "lea",
    "push", "pop", "extend", "unary", "shift", "mul", "imul3", "bt", "cbw",
    "cwd", "xchg", "leave", "call", "jmp", "ret", "vmov", "vfp" or "vlane".
    form is the destination's kind then the source's (r, m or i, or x for an
    XMM register), then for IMUL3 an i if it takes an immediate too; for MUL
    and IMUL with one operand it is the source's, for CBW the destination's,
    for CALL and JMP the target's (i for CALL rel32), for RET i and for
    LEAVE r. shape and seg are the memory operand's, if any. ordered is for
    the twin that keeps the guest's memory order (tcg_ldst_ordered()).
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
        if self.kind == "imul3":
            return self.form in ("rr", "rm")
        if self.kind == "vfp":
            return self.op.reads_d
        return self.kind in ("alu", "unary", "shift", "bt", "cbw", "xchg",
                             "vlane")

    @property
    def accesses_memory(self):
        # LEA's memory operand is only an address.
        return (self.has_mem and self.kind != "lea"
                or self.kind in ("push", "pop", "call", "ret", "leave"))

    @property
    def loads(self):
        """ Whether the gadget loads from guest memory: MOV to memory only
        stores. """
        if self.kind in ("pop", "ret", "leave"):
            return True
        return (self.has_mem and self.kind != "lea" and
                not (self.kind in ("mov", "vmov") and self.form[0] == "m"))

    @property
    def stores(self):
        """ Whether the gadget stores to guest memory: CMP and TEST, and a
        memory source, only load. """
        if self.kind in ("push", "call"):
            return True
        return (self.has_mem and self.form[0] == "m" and
                (self.kind in ("mov", "vmov", "unary", "shift") or
                 self.kind in ("alu", "bt") and self.op.writes))

    @property
    def stream(self):
        """ The stream words, from stream_words(). """
        # rcg_emit() packs a gadget's words when its slot accesses memory,
        # and stream_words() when they hold a tlb word.
        assert ("tlb" in self.words) == self.accesses_memory, self.name
        return stream_words(self.words)

    @property
    def words(self):
        """ The gadget's operand words, in the translator's order before
        packing (see stream): the destination's, then the source's, then for
        a memory access the MemOpIdx and the env offset of the MMU index's
        CPUTLBDescFast (TCTI_TLB_FAST_OFS()). A register operand is its env
        offset in CPUX86State.regs[]: "d" if it is written, "s" if only read
        (or XCHG's source, which it writes too), and "s1" for CMP's, TEST's
        and BT's first operand, which is only read. A memory operand is the
        words of its shape (ea_words()). An immediate is its value,
        sign-extended as decode-new extends it.

        CALL's imm is the return address less env's eip, and RET's how far
        it moves RSP. MUL and IMUL with one operand take no words for RAX
        and RDX, whose offsets are fixed, nor LEAVE for RBP and RSP. """
        if self.kind in ("call", "jmp", "ret"):
            words = (ea_words(self.shape, self.seg) if self.form == "m"
                     else ["s"] if self.form == "r" else [])
            if self.kind != "jmp":
                words.append("imm")
            if self.accesses_memory:
                words += ["oi", "tlb"]
            return words
        if self.kind == "leave":
            operands = []
        elif self.kind in ("push", "mul"):
            operands = ["s" if self.form == "r" else self.form]
        elif self.kind == "imul3":
            operands = ["d", "s" if self.form[1] == "r" else "m",
                        *self.form[2:]]
        elif self.kind in ("pop", "unary", "cbw"):
            operands = ["d" if self.form == "r" else self.form]
        else:
            operands = ["d" if self.form[0] in "rx" else self.form[0]]
            if self.kind != "zero":
                operands.append("s" if self.form[1] in "rx"
                                else self.form[1])
            if (self.kind in ("alu", "bt") and not self.op.writes and
                    operands[0] == "d"):
                operands[0] = "s1"
        words = []
        for operand in operands:
            if operand == "m":
                words += ea_words(self.shape, self.seg)
            elif operand == "i":
                words.append("imm")
            else:
                words.append(operand)
        if self.kind == "shift" and self.form[1] == "r":
            words.append("ccop")
        if self.accesses_memory:
            words += ["oi", "tlb"]
        return words

    @property
    def cf(self):
        """ Where the translator puts CF from before the instruction, which
        it takes from the flags state and a gadget cannot, as RCG_CF_<this>:
        "SRC2" before the gadget, which reads it (ADC and SBB, as gen_ADC
        and gen_SBB leave it); "SRC" after the gadget, which leaves cc_src
        alone (INC and DEC, which keep it, as gen_INC and gen_DEC do); or
        "NONE". """
        if self.kind == "alu" and self.op.cc in ("ADC", "SBB"):
            return "SRC2"
        if self.kind == "unary" and self.op.cc in ("INC", "DEC"):
            return "SRC"
        return "NONE"

    @property
    def cc_writes(self):
        """ Which of cc_dst, cc_src and cc_src2 the gadget writes, as TCG's
        decode.cc_dst, cc_src and cc_src2 say for the instruction, except
        for what cf says the translator writes. After a "SUB" one, the
        translator must also keep cc_srcT = cc_dst + cc_src, the original
        first operand, as TCG's gen_SUB does (0 after NEG, which is the same
        sum). """
        if self.kind == "zero":
            return ("cc_src",)
        if self.kind == "alu":
            if self.op.cc == "LOGIC":
                return ("cc_dst",)
            return ("cc_dst", "cc_src")
        if self.cf == "SRC":
            return ("cc_dst",)
        if (self.kind in ("unary", "shift") and self.op.cc or
                self.kind in ("mul", "imul3")):
            return ("cc_dst", "cc_src")
        if self.kind == "bt":
            return ("cc_src",)
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
    for op in SHIFT_OPS:
        for form in ("rr", "mr"):
            for width in WIDTHS:
                yield from with_memory(Spec("shift", op, form, width))
    for width in ROTATE_WIDTHS:
        yield Spec("shift", ROTATE_OP, "ri", width)
    for op in MUL_OPS:
        for form in ("r", "m"):
            for width in WIDTHS:
                yield from with_memory(Spec("mul", op, form, width))
    for form in IMUL3_FORMS:
        for width in IMUL3_WIDTHS:
            yield from with_memory(Spec("imul3", IMUL3_OP, form, width))
    for op in BT_OPS:
        for form in BT_FORMS:
            for width in BT_WIDTHS:
                yield from with_memory(Spec("bt", op, form, width))
    for width in CBW_WIDTHS:
        yield Spec("cbw", None, "r", width)
        yield Spec("cwd", None, "rr", width)
    for width in XCHG_WIDTHS:
        yield Spec("xchg", None, "rr", width)
    yield from with_memory(Spec("leave", None, "r", 64))
    for form in ("i", "r", "m"):
        yield from with_memory(Spec("call", None, form, 64))
    for form in ("r", "m"):
        yield from with_memory(Spec("jmp", None, form, 64))
    yield from with_memory(Spec("ret", None, "i", 64))
    for op in VMOV_OPS:
        for form in ("xx", "xm", "mx"):
            yield from with_memory(Spec("vmov", op, form, op.width))
    for op in VFP_OPS:
        for form in ("xx", "xm"):
            yield from with_memory(Spec("vfp", op, form, op.width))
    for op in VLANE_OPS:
        for form in ("xx", "xm"):
            yield from with_memory(Spec("vlane", op, form, op.width))


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

# A gadget's operand words arrive in these registers, in order, however the
# spec's stream holds them. They are none of x0-x4, which a slow path sets
# up as a helper's arguments before it is done with the words.
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

    def enter(self, stream):
        """ The lines that load the gadget's operand words into their
        registers: stream holds, for each of the spec's stream words, the
        registers of its words. """
        raise NotImplementedError

    def leave(self):
        """ The lines that end the gadget, going on to what follows it. """
        raise NotImplementedError

    def branch(self, arm, labels):
        """ The lines that make the gadget go on at its target instead, if
        the host's condition arm holds. labels are numeric labels reserved
        for these lines, so they cannot clash with those of a load in the
        same body. """
        raise NotImplementedError

    def jumps(self, arm, labels):
        """ The lines on the way through and the slow-path lines of a branch
        if arm holds that also makes the jump to the next TB each way, for
        jccgoto and fjccgoto (see tcg_gen_rich_br()), with labels as for
        branch(). """
        raise NotImplementedError

    def assemble(self, stream, hot, cold):
        """ The whole gadget, from the stream words' registers, the body's
        lines on the way through and its slow paths. """
        return [*self.enter(stream), *hot, *self.leave(), *cold]


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
        layout = self.spec.stream
        assert sorted(sum(layout, ())) == sorted(self.spec.words), \
            self.spec.name
        stream = [tuple(map(self.word, words)) for words in layout]
        return self.h.assemble(stream, self.hot, self.cold)

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

    def load128(self, lo, hi, addr, aligned):
        """ lo and hi = the 16 bytes of guest memory at addr, as TCTI's
        qemu_ld_i128 gadgets load them: one LDP. The translator requires
        LSE2, which makes an aligned LDP single-copy atomic. aligned
        says the access must be on a 16-byte boundary: one that is not goes
        to the helper, which raises the fault. The ordered twin orders it
        before what follows with DMB ISHLD, as those gadgets do. """
        t, out, page = tcti_memory.TMP
        miss, join = self._labels()
        if aligned:
            self.emit(f"tst {addr}, #15", f"b.ne {miss}f")
        self.emit(*tcti_memory.create_tlb_fastpath(
            is_write=False, size=16, addr=addr, miss_label=miss,
            env=self.env, tlb=self.word("tlb"), cmp_operand="tlb_cmp_read"),
                  f"add {out}, {out}, {addr}",
                  f"ldp {lo}, {hi}, [{out}]",
                  f"{join}:")
        if self.spec.ordered:
            self.emit("dmb ishld")
        save, restore = self._save(self.used | set(self.word_regs.values()))
        self.cold += [
            f"{miss}:",
            f"mov {out}, {addr}",
            *save,
            f"mov x0, {self.env}",
            f"mov x1, {out}",
            self._memop().format("x2"),
            f"mov x3, {self.h.retaddr}",
            "bl _helper_ld16_mmu",
            # Int128 comes back in x0 and x1, which restore may reload.
            f"mov {t}, x0",
            f"mov {page}, x1",
            *restore,
            f"mov {lo}, {t}",
            f"mov {hi}, {page}",
            f"b {join}b",
        ]
        self.define(lo, hi)

    def store128(self, lo, hi, addr, aligned):
        """ The 16 bytes of lo and hi to guest memory at addr, as load128()
        loads them, with one STP; the ordered twin puts DMB ISHST before
        it. """
        t, out, page = tcti_memory.TMP
        miss, join = self._labels()
        if aligned:
            self.emit(f"tst {addr}, #15", f"b.ne {miss}f")
        self.emit(*tcti_memory.create_tlb_fastpath(
            is_write=True, size=16, addr=addr, miss_label=miss,
            env=self.env, tlb=self.word("tlb"), cmp_operand="tlb_cmp_write"),
                  f"add {out}, {out}, {addr}",
                  *(["dmb ishst"] if self.spec.ordered else []),
                  f"stp {lo}, {hi}, [{out}]",
                  f"{join}:")
        save, restore = self._save(self.used | set(self.word_regs.values()))
        self.cold += [
            f"{miss}:",
            # Out of the way of the helper's arguments.
            f"mov {t}, {addr}",
            f"mov {out}, {lo}",
            f"mov {page}, {hi}",
            *save,
            f"mov x0, {self.env}",
            f"mov x1, {t}",
            f"mov x2, {out}",
            f"mov x3, {page}",
            self._memop().format("x4"),
            f"mov x5, {self.h.retaddr}",
            *(["dmb ishst"] if self.spec.ordered else []),
            "bl _helper_st16_mmu",
            *restore,
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
        gen_op_mov_v_reg() reads it for any width but AH to BH. For those
        the word is the offset of RAX to RBX plus 1 (see rcg_reg_op() in
        rcg.c.inc), so that dest's low byte is the register and the rest
        reaches into the next one: a gadget the translator gives them to
        uses no more of dest than its low byte. """
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

    def cond(self, cls, width, cond, fused=False):
        """ Sets the host's flags from the lazy-flags state cls at width
        (as CC_OP_<cls>B + the width's MemOp would read), and returns the
        AArch64 condition under which x86 condition cond holds. Values are
        compared shifted to the top of a register, so that the host's N, Z,
        C and V are the guest's at width. fused says that alu_body() has
        just left the state, so that the values are still in registers: a
        SUB's operands in A and B, a LOGIC's result in R. """
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
        elif cls == "sar":
            # As compute_aco_sar() reads it: CF is cc_src's bit 0, OF is the
            # top bit at the width of cc_src ^ cc_dst, and ZF and SF come
            # from cc_dst, so that SF ^ OF is cc_src's top bit.
            self.emit(f"ldp {A}, {B}, [{env}, %[cc_dst]]")
            if jcc_op == 0:
                self.emit(f"eor {T}, {A}, {B}")
                top(T)
                self.emit(f"tst {T}, {T}")
                arm = "mi"
            elif jcc_op == 1:
                self.emit(f"tst {B}, #1")
                arm = "ne"
            elif jcc_op == 2:
                top(A)
                self.emit(f"tst {A}, {A}")
                arm = "eq"
            elif jcc_op == 3:
                # CF or ZF: 1 if Z, else C.
                top(A)
                self.emit(f"and {T}, {B}, #1",
                          f"cmp {A}, #0",
                          f"csinc {T}, {T}, xzr, ne",
                          f"cmp {T}, #0")
                arm = "ne"
            elif jcc_op == 4:
                top(A)
                self.emit(f"tst {A}, {A}")
                arm = "mi"
            elif jcc_op == 6:
                top(B)
                self.emit(f"tst {B}, {B}")
                arm = "mi"
            else:
                # SF ^ OF, or ZF: 1 if Z, else cc_src's top bit. P is read
                # from CC_OP_EFLAGS only (see cond_specs()).
                assert jcc_op == 7
                top(A)
                top(B)
                self.emit(f"lsr {T}, {B}, #63",
                          f"cmp {A}, #0",
                          f"csinc {T}, {T}, xzr, ne",
                          f"cmp {T}, #0")
                arm = "ne"
        else:
            if not fused:
                self.emit(f"ldp {A}, {B}, [{env}, %[cc_dst]]")
            elif cls == "logic":
                self.emit(f"mov {A}, {R}")
            else:
                assert cls == "sub"
            if cls in ("sub", "add"):
                # SUB: cc_dst + cc_src is cc_srcT, the first operand; ADD:
                # cc_dst - cc_src is it. A fused SUB still has it in A.
                if not fused:
                    self.emit(f"{'add' if cls == 'sub' else 'sub'} "
                              f"{A}, {A}, {B}")
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
        self.emit(*self.h.branch(arm, self._labels()))

    def jumps(self, arm):
        """ The harness's branch if arm holds, then the jump each way. """
        hot, cold = self.h.jumps(arm, (*self._labels(), *self._labels()))
        self.emit(*hot)
        self.cold += cold

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
    # ADC and SBB then add or subtract CF, which the translator has put in
    # cc_src2.
    if spec.cf == "SRC2":
        g.emit(f"ldr {T}, [{g.env}, %[cc_src2]]",
               f"{op.a64} {R}, {R}, {T}")
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


def vmov_body(g, spec):
    # gen_MOVDQ: the 16 bytes of the source, an XMM register in env or
    # memory, to the destination (MOVSD and MOVSS: scalar_vmov_body()).
    # Each form has at most one memory access, and nothing is written
    # before it.
    aligned = spec.op.aligned
    if spec.has_mem:
        g.ea(ADDR)
    if spec.width < 128:
        scalar_vmov_body(g, spec)
        return
    if spec.form[1] == "m":
        g.load128(A, B, ADDR, aligned)
    else:
        g.emit(f"add {T}, {g.env}, {g.word('s')}",
               f"ldp {A}, {B}, [{T}]")
        g.define(A, B)
    if spec.form[0] == "m":
        g.store128(A, B, ADDR, aligned)
    else:
        g.emit(f"add {T}, {g.env}, {g.word('d')}",
               f"stp {A}, {B}, [{T}]")


def scalar_vmov_body(g, spec):
    # MOVSD and MOVSS, once vmov_body has formed the address: the low lane of
    # the source to the destination. A load clears the rest of the register:
    # one STP stores the lane, zero-extended, and XZR above it.
    width = spec.width
    lane = w if width == 32 else (lambda r: r)
    if spec.form[1] == "m":
        g.load(A, ADDR, width)
    else:
        g.emit(f"ldr {lane(A)}, [{g.env}, {g.word('s')}]")
        g.define(A)
    if spec.form[0] == "m":
        g.store(A, ADDR, width)
    elif spec.form[1] == "m":
        g.emit(f"add {T}, {g.env}, {g.word('d')}",
               f"stp {A}, xzr, [{T}]")
    else:
        g.emit(f"str {lane(A)}, [{g.env}, {g.word('d')}]")


# MXCSR's rounding control and flush-to-zero bits, and denormals-are-zero.
MXCSR_RC_FZ = 0xe000
MXCSR_DAZ_BIT = 6

# By lane width: the smallest normal's magnitude shifted left by one, which
# drops the sign; infinity's, shifted the same way, less that; and the
# exponent's bits.
VFP_MIN_NORMAL2 = {32: 0x01000000, 64: 0x0020000000000000}
VFP_SPAN = {32: 0xfe000000, 64: 0xffc0000000000000}
VFP_EXP = {32: 0x7f800000, 64: 0x7ff0000000000000}

# By lane width, for SQRT: the smallest normal, and infinity's bits less
# those. A positive normal less the first is below the second, unsigned, and
# nothing else is.
VFP_MIN_NORMAL = {32: 0x00800000, 64: 0x0010000000000000}
VFP_SQRT_SPAN = {32: 0x7f000000, 64: 0x7fe0000000000000}


def vfp_body(g, spec):
    # gen_fp_sse()'s or gen_unary_fp_sse()'s helper, on the host's FPU when
    # the host's result is sure to be the helper's and to leave the
    # exception flags as they are, which needs everything ops_sse_host.h
    # checks, and more:
    #  - MXCSR rounds to nearest and flushes nothing (sse_host_mode_ok()).
    #  - PE is set already, so whether the op was exact cannot show.
    #  - No input lane is denormal, which would raise DE.
    #  - Every result lane is normal and above the smallest normal. That
    #    rules out a NaN (an invalid op, or a NaN input, which raise IE or
    #    take x86's NaN rules), an infinity (OE, ZE or an infinite input)
    #    and a tiny result (UE: a result of exactly the smallest normal may
    #    have been rounded up from a tiny one, which x86 counts as an
    #    underflow), and with them every case where the host's result could
    #    differ.
    # For SQRT, the last two give way to a positive normal input lane, whose
    # root is normal and raises nothing but PE.
    # Anything else goes to the helper, and so to ops_sse_host.h or
    # softfloat. The load comes first, as it may fault.
    op, env = spec.op, g.env
    lane = op.lane
    slow, join = g._labels()
    if spec.has_mem:
        g.ea(ADDR)
        if op.packed:
            g.load128(A, B, ADDR, aligned=True)
        else:
            g.load(B, ADDR, lane)
    g.emit(f"ldr {w(R)}, [{env}, %[mxcsr]]",
           f"ldrh {w(T)}, [{env}, %[sse_flags]]",
           f"tst {w(R)}, #{MXCSR_RC_FZ:#x}",
           f"b.ne {slow}f",
           f"tbnz {w(R)}, #{MXCSR_DAZ_BIT}, {slow}f",
           f"tbz {w(T)}, #%[sse_inexact], {slow}f")
    if op.packed:
        packed_vfp_lines(g, spec, slow)
    else:
        scalar_vfp_lines(g, spec, slow)
    g.emit(f"{join}:")

    # The helper writes the destination. A memory source goes to xmm_t0
    # first: TCG's gen_load_sse() loads it there for the helper too.
    save, restore = g._save(())
    store = []
    # The helper takes (env, d, d, s), or for packed SQRT, which has no
    # second input, (env, d, s): the source goes in x3, or x2.
    arg = "x2" if op.unary and op.packed else "x3"
    if not spec.has_mem:
        source = f"add {arg}, {env}, {g.word('s')}"
    else:
        source = f"add {arg}, {env}, %[xmm_t0]"
        if op.packed:
            store = [f"add {T}, {env}, %[xmm_t0]", f"stp {A}, {B}, [{T}]"]
        else:
            lane_reg = w(B) if lane == 32 else B
            store = [f"str {lane_reg}, [{env}, %[xmm_t0]]"]
    args = [source] if arg == "x2" else ["mov x2, x1", source]
    g.cold += [
        f"{slow}:",
        *store,
        *save,
        f"mov x0, {env}",
        f"add x1, {env}, {g.word('d')}",
        *args,
        f"bl _{op.helper}",
        *restore,
        f"b {join}b",
    ]


def scalar_vfp_lines(g, spec, slow):
    """ The low lane of the destination, in A, op that of the source, in B
    (loaded already for a memory source), to R, checked as vfp_body()
    says, and stored; or for SQRT, the root of the source's low lane, from
    B, in s0 or d0, checked as vfp_body() says, and stored. """
    op, env, lane = spec.op, g.env, spec.op.lane
    r = w if lane == 32 else (lambda x: x)
    f = "s" if lane == 32 else "d"
    if not spec.has_mem:
        g.emit(f"ldr {r(B)}, [{env}, {g.word('s')}]")
    if op.unary:
        # The destination counts as read: its other lanes stay.
        g.reads.add("d")
        g.emit(f"mov {r('x13')}, #{VFP_MIN_NORMAL[lane]:#x}",
               f"sub {r(T)}, {r(B)}, {r('x13')}",
               f"mov {r('x24')}, #{VFP_SQRT_SPAN[lane]:#x}",
               f"cmp {r(T)}, {r('x24')}",
               f"b.hs {slow}f",
               f"fmov {f}1, {r(B)}",
               f"{op.a64} {f}0, {f}1",
               f"str {f}0, [{env}, {g.word('d')}]")
        return
    g.emit(f"ldr {r(A)}, [{env}, {g.word('d')}]")
    g.reads.add("d")
    g.emit(f"fmov {f}0, {r(A)}",
           f"fmov {f}1, {r(B)}",
           f"{op.a64} {f}0, {f}0, {f}1",
           f"fmov {r(R)}, {f}0",
           # The result's magnitude, doubled, less the smallest normal's:
           # 0 for the smallest normal, wrapped around for smaller ones, and
           # SPAN or more for an infinity or a NaN.
           f"lsl {r(T)}, {r(R)}, #1",
           f"mov {r('x13')}, #{VFP_MIN_NORMAL2[lane]:#x}",
           f"sub {r(T)}, {r(T)}, {r('x13')}",
           f"mov {r('x24')}, #{VFP_SPAN[lane]:#x}",
           f"cmp {r(T)}, {r('x24')}",
           f"ccmp {r(T)}, #0, #4, lo",
           f"b.eq {slow}f")
    # A denormal input: exponent 0, and not a zero.
    for reg in (A, B):
        g.emit(f"lsl {r(T)}, {r(reg)}, #1",
               f"tst {r(reg)}, #{VFP_EXP[lane]:#x}",
               f"ccmp {r(T)}, #0, #4, eq",
               f"b.ne {slow}f")
    g.emit(f"str {r(R)}, [{env}, {g.word('d')}]")


def packed_vfp_lines(g, spec, slow):
    """ The same on every lane: the destination in v0 (for SQRT, which
    has no second input, not loaded), the source in v1 (from A and B for a
    memory source), the result in v2. """
    op, env, lane = spec.op, g.env, spec.op.lane
    t = "4s" if lane == 32 else "2d"
    r = w if lane == 32 else (lambda x: x)
    if spec.has_mem:
        g.emit(f"fmov d1, {A}",
               f"mov v1.d[1], {B}")
    else:
        g.emit(f"ldr q1, [{env}, {g.word('s')}]")
    if op.unary:
        g.emit(f"mov {r('x13')}, #{VFP_MIN_NORMAL[lane]:#x}",
               f"dup v4.{t}, {r('x13')}",
               f"sub v3.{t}, v1.{t}, v4.{t}",
               f"mov {r('x24')}, #{VFP_SQRT_SPAN[lane]:#x}",
               f"dup v5.{t}, {r('x24')}",
               f"cmhs v6.{t}, v3.{t}, v5.{t}",
               "umaxv s6, v6.4s",
               f"fmov {w(T)}, s6",
               f"cbnz {w(T)}, {slow}f",
               f"{op.a64} v2.{t}, v1.{t}",
               f"str q2, [{env}, {g.word('d')}]")
        return
    g.emit(f"ldr q0, [{env}, {g.word('d')}]")
    g.reads.add("d")
    g.emit(f"{op.a64} v2.{t}, v0.{t}, v1.{t}",
           # As in scalar_vfp_lines(), on each lane: v6 collects the bad
           # ones.
           f"shl v3.{t}, v2.{t}, #1",
           f"mov {r('x13')}, #{VFP_MIN_NORMAL2[lane]:#x}",
           f"dup v4.{t}, {r('x13')}",
           f"sub v3.{t}, v3.{t}, v4.{t}",
           f"mov {r('x24')}, #{VFP_SPAN[lane]:#x}",
           f"dup v5.{t}, {r('x24')}",
           f"cmhs v6.{t}, v3.{t}, v5.{t}",
           f"cmeq v7.{t}, v3.{t}, #0",
           "orr v6.16b, v6.16b, v7.16b")
    # A denormal input: below the smallest normal, and not a zero.
    for v in ("v0", "v1"):
        g.emit(f"shl v3.{t}, {v}.{t}, #1",
               f"cmhi v7.{t}, v4.{t}, v3.{t}",
               f"cmeq v16.{t}, v3.{t}, #0",
               "bic v7.16b, v7.16b, v16.16b",
               "orr v6.16b, v6.16b, v7.16b")
    g.emit("umaxv s6, v6.4s",
           f"fmov {w(T)}, s6",
           f"cbnz {w(T)}, {slow}f",
           f"str q2, [{env}, {g.word('d')}]")


def vlane_body(g, spec):
    # The punpckl and punpckh helpers' lanes: low halves for UNPCKL, high
    # ones for UNPCKH, the destination's lane first. A memory source is all
    # 16 bytes, aligned, which gen_load_sse() loads too.
    op, env = spec.op, g.env
    if spec.has_mem:
        g.ea(ADDR)
        g.load128(A, B, ADDR, aligned=True)
        g.emit(f"fmov d1, {A}",
               f"mov v1.d[1], {B}")
    else:
        g.emit(f"ldr q1, [{env}, {g.word('s')}]")
    g.emit(f"ldr q0, [{env}, {g.word('d')}]")
    g.reads.add("d")
    t = "4s" if op.lane == 32 else "2d"
    g.emit(f"zip{2 if op.high else 1} v2.{t}, v0.{t}, v1.{t}",
           f"str q2, [{env}, {g.word('d')}]")


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
    if spec.cf == "SRC":
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
    if spec.form[0] == "m":
        g.ea(ADDR)
        g.load(A, ADDR, width)
        if op.signed:
            g.extend(A, width, True)
    else:
        g.read_reg(A, "d")
        g.extend(A, width, op.signed)
    by_cl = spec.form[1] == "r"
    if by_cl:
        # The count from CL, masked as x86 masks it.
        g.read_reg(T, "s")
        g.emit(f"and {T}, {T}, #{0x3f if width == 64 else 0x1f}")
        count = T
    else:
        count = g.word("imm")
    g.emit(f"sub {B}, {count}, #1",
           f"{op.a64} {B}, {A}, {B}",
           f"{op.a64} {R}, {A}, {count}")
    g.define(B, R)
    if by_cl:
        # Kept for after the write, which may use T.
        g.emit(f"mov {A}, {T}")
    if spec.form[0] == "m":
        g.store(R, ADDR, width)
    else:
        g.write_reg(R, "d", width)
    if not by_cl:
        g.write_cc(dst=R, src=B)
        return
    # A count of 0 keeps the flags state, storing cc_op as it was unless
    # the translator did not know it, in which case env already has it.
    zero, join = g._labels()
    old = w(g.word("ccop"))
    g.emit(f"cbz {A}, {zero}f",
           f"mov {w(T)}, %[cc_op_{op.cc.lower()}b] + {WIDTHS.index(width)}",
           f"str {w(T)}, [{g.env}, %[cc_op]]")
    g.write_cc(dst=R, src=B)
    g.emit(f"{join}:")
    g.cold += [f"{zero}:",
               f"cmp {old}, %[cc_op_dynamic]",
               f"b.eq {join}b",
               f"str {old}, [{g.env}, %[cc_op]]",
               f"b {join}b"]


def mul_body(g, spec):
    # gen_MUL and gen_IMUL: RAX times the source, both extended from the
    # operand size, so that below 64 bits one MUL makes the whole product.
    op, width, env = spec.op, spec.width, g.env
    if spec.form == "m":
        g.ea(ADDR)
        g.load(B, ADDR, width)
    else:
        g.read_reg(B, "s")
    g.emit(f"ldr {A}, [{env}, %[rax]]")
    g.define(A)
    g.extend(A, width, op.signed)
    g.extend(B, width, op.signed)
    g.emit(f"mul {R}, {A}, {B}")
    g.define(R)
    if width == 64:
        # RDX the high half, and for IMUL cc_src the low half's sign less
        # the high half.
        g.emit(f"{'smulh' if op.signed else 'umulh'} {T}, {A}, {B}",
               f"str {R}, [{env}, %[rax]]",
               f"str {T}, [{env}, %[rdx]]")
        if op.signed:
            g.emit(f"asr {B}, {R}, #63",
                   f"sub {B}, {B}, {T}")
            g.write_cc(dst=R, src=B)
        else:
            g.write_cc(dst=R, src=T)
        return
    # AX at 8 bits; AX and DX at 16; EAX and EDX, zero-extended, at 32.
    if width == 32:
        g.emit(f"mov {w(A)}, {w(R)}",
               f"lsr {T}, {R}, #32",
               f"str {A}, [{env}, %[rax]]",
               f"str {T}, [{env}, %[rdx]]")
    else:
        g.emit(f"strh {w(R)}, [{env}, %[rax]]")
        if width == 16:
            g.emit(f"lsr {T}, {R}, #16",
                   f"strh {w(T)}, [{env}, %[rdx]]")
    if op.signed:
        # cc_src: the product truncated and sign-extended, less the product.
        g.emit(f"sxt{ {8: 'b', 16: 'h', 32: 'w'}[width] } {B}, {w(R)}",
               f"sub {B}, {B}, {R}")
        g.write_cc(dst=R, src=B)
    elif width == 8:
        g.emit(f"and {B}, {R}, #0xff00")
        g.write_cc(dst=R, src=B)
    elif width == 16:
        g.write_cc(dst=R, src=T)
    else:
        # cc_dst and cc_src: EAX and EDX as written, as gen_MUL leaves
        # them.
        g.write_cc(dst=A, src=T)


def imul3_body(g, spec):
    # gen_IMUL3: both operands sign-extended from the operand size, so that
    # below 64 bits one MUL makes the whole product, which TCG keeps in
    # cc_dst.
    width, form = spec.width, spec.form
    if spec.has_mem:
        g.ea(ADDR)
        g.load(A, ADDR, width)
    else:
        g.read_reg(A, "s")
    if form.endswith("i"):
        g.emit(f"mov {B}, {g.word('imm')}")
        g.define(B)
    else:
        g.read_reg(B, "d")
    g.extend(A, width, True)
    g.extend(B, width, True)
    g.emit(f"mul {R}, {A}, {B}")
    g.define(R)
    if width == 64:
        # cc_src: the low half's sign less the high half.
        g.emit(f"smulh {T}, {A}, {B}",
               f"asr {B}, {R}, #63",
               f"sub {B}, {B}, {T}")
    else:
        g.emit(f"sxt{ {16: 'h', 32: 'w'}[width] } {B}, {w(R)}",
               f"sub {B}, {B}, {R}")
    g.write_reg(R, "d", width)
    g.write_cc(dst=R, src=B)


def bt_body(g, spec):
    # gen_BT, gen_BTS, gen_BTR and gen_BTC, after any state except those
    # BitTest excludes, leaving CC_OP_SARB plus that state's MemOp: the
    # operand is written back first, as it may fault, then cc_src.
    op, width = spec.op, spec.width
    if spec.has_mem:
        g.ea(ADDR)
        g.load(A, ADDR, width)
    else:
        g.read_reg(A, "d" if op.writes else "s1")
    if spec.form[1] == "r":
        g.read_reg(B, "s")
        g.emit(f"and {B}, {B}, #{width - 1}")
        bit = B
    else:
        # The translator masks it.
        bit = g.word("imm")
    if op.writes:
        g.emit(f"mov {R}, #1",
               f"lsl {R}, {R}, {bit}",
               f"{op.a64} {R}, {A}, {R}")
        g.define(R)
        if spec.has_mem:
            g.store(R, ADDR, width)
        else:
            g.write_reg(R, "d", width)
    g.emit(f"lsr {T}, {A}, {bit}")
    g.write_cc(src=T)


def cbw_body(g, spec):
    # gen_CBW: RAX's low half sign-extended, at the operand size.
    width = spec.width
    g.read_reg(A, "d")
    g.extend(A, width // 2, True)
    g.write_reg(A, "d", width)


def cwd_body(g, spec):
    # gen_CWD: RDX filled with the sign of RAX at the operand size.
    width = spec.width
    g.read_reg(A, "s")
    g.emit(f"sbfx {A}, {A}, #{width - 1}, #1")
    g.write_reg(A, "d", width)


def xchg_body(g, spec):
    # gen_XCHG of two registers: each gets the other's value, written at
    # the operand size.
    width = spec.width
    g.read_reg(A, "d")
    g.read_reg(B, "s")
    g.write_reg(B, "d", width)
    g.write_reg(A, "s", width)


def leave_body(g, spec):
    # gen_leave() for 64-bit code: RBP from the stack at RBP, and RSP just
    # above it. The load comes first, as it may fault.
    env = g.env
    g.emit(f"ldr {B}, [{env}, %[rbp]]")
    g.define(B)
    g.load(A, B, 64)
    g.emit(f"add {B}, {B}, #8",
           f"str {A}, [{env}, %[rbp]]",
           f"str {B}, [{env}, %[rsp]]")


def jcc_body(g, spec):
    # gen_Jcc's condition and branch; the translator must emit the jumps on
    # either side. The gadget always stores CC_OP first, as gen_jcc() does
    # when cc_op is dirty, so that the translator need not.
    g.emit(f"str {w(g.word('ccop'))}, [{g.env}, %[cc_op]]")
    g.branch(g.cond(spec.cls, spec.cc_width, spec.cond))


def jccgoto_body(g, spec):
    # jcc_body's work, then the jump to the next TB that each way starts
    # with, in the same dispatch.
    g.emit(f"str {w(g.word('ccop'))}, [{g.env}, %[cc_op]]")
    g.jumps(g.cond(spec.cls, spec.cc_width, spec.cond))


def fused_body(g, spec):
    # The CMP's or TEST's body, then jcc_body's or jccgoto_body's on the
    # values the setter left in registers.
    alu_body(g, spec.setter)
    g.emit(f"str {w(g.word('ccop'))}, [{g.env}, %[cc_op]]")
    arm = g.cond(spec.cls, spec.setter.width, spec.cond, fused=True)
    if spec.kind == "fjcc":
        g.branch(arm)
    else:
        g.jumps(arm)


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
    "jccgoto": jccgoto_body,
    "vmov": vmov_body,
    "vfp": vfp_body,
    "vlane": vlane_body,
    "fjcc": fused_body,
    "fjccgoto": fused_body,
    "setcc": setcc_body,
    "cmov": cmov_body,
    "mul": mul_body,
    "imul3": imul3_body,
    "bt": bt_body,
    "cbw": cbw_body,
    "cwd": cwd_body,
    "xchg": xchg_body,
    "leave": leave_body,
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
# directly, and the exit request's offset for TctiHarness.jumps().
BODY_OPERANDS = {
    "tlb_shift": "TCTI_TLB_INDEX_SHIFT",
    "tlb_cmp_read": "offsetof(CPUTLBEntry, addr_read)",
    "tlb_cmp_write": "offsetof(CPUTLBEntry, addr_write)",
    "tlb_addend": "offsetof(CPUTLBEntry, addend)",
    "tlb_page_mask": "TCTI_TLB_PAGE_MASK",
    "cc_dst": "offsetof(CPUX86State, cc_dst)",
    "cc_src": "offsetof(CPUX86State, cc_src)",
    "cc_src2": "offsetof(CPUX86State, cc_src2)",
    "rax": "offsetof(CPUX86State, regs[R_EAX])",
    "rdx": "offsetof(CPUX86State, regs[R_EDX])",
    "rsp": f"offsetof(CPUX86State, regs[{R_ESP}])",
    "rbp": "offsetof(CPUX86State, regs[R_EBP])",
    "eip": "offsetof(CPUX86State, eip)",
    "cc_z_p": "CC_Z | CC_P",
    "cc_op": "offsetof(CPUX86State, cc_op)",
    "cc_op_shlb": "CC_OP_SHLB",
    "cc_op_sarb": "CC_OP_SARB",
    "cc_op_dynamic": "CC_OP_DYNAMIC",
    "cc_s": "CC_S",
    "eflags_0": "CC_O",
    "eflags_1": "CC_C",
    "eflags_2": "CC_Z",
    "eflags_3": "CC_Z | CC_C",
    "eflags_4": "CC_S",
    "eflags_5": "CC_P",
    "exit_ofs": "TCTI_EXIT_REQUEST_OFS",
    "mxcsr": "offsetof(CPUX86State, mxcsr)",
    "sse_flags": "offsetof(CPUX86State, sse_status)",
    "sse_inexact": "__builtin_ctz(float_flag_inexact)",
    "xmm_t0": "offsetof(CPUX86State, xmm_t0)",
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
    # vfp_body() adds xmm_t0's offset as an ADD immediate.
    "offsetof(CPUX86State, xmm_t0) > 4095",
)


class CheckHarness(Harness):
    """ A harness that only marks where a gadget is entered, branches and
    leaves, so that check() can render every body without building it. """

    def enter(self, stream):
        return [f"// enter: {', '.join(r for regs in stream for r in regs)}"]

    def leave(self):
        return ["// leave"]

    def branch(self, arm, labels):
        return [f"// branch if {arm}"]

    def jumps(self, arm, labels):
        return [f"// jumps if {arm}"], []


def check():
    """ Renders every gadget's body, the condition gadgets' included, and
    checks that each names only the asm operands of BODY_OPERANDS and the
    registers a body may use, none of V8 to V15, which TCTI expects
    unchanged, that every branch it makes has a label to go to, and that it
    reads its "d" register only if reads_d says so. Returns how many
    gadgets were checked. """
    h = CheckHarness()
    allowed = {*h.scratch, h.env, h.retaddr, "x15", "sp", "lr", "xzr"}
    names = set()
    for spec in [*specs(), *cond_specs(), *fused_specs()]:
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
            for reg in re.findall(r"(?<![.%])\b[vqdsh](\d+)\b", line):
                assert not 8 <= int(reg) <= 15, (spec.name, line)
            for target in re.findall(r"(?<!\.)\b(\d+)[bf]\b", line):
                assert target in labels, (spec.name, line)
    return len(names)


#
# TCTI's gadgets, and the translator's table of them.
#

class TctiHarness(Harness):
    """ TCTI's streams: tcg_out_rich() writes a gadget's address, then its
    operand words, in the spec's stream words. The gadget loads the words
    first, so x28, the return address its slow paths pass, points past
    them. """

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

    def assemble(self, stream, hot, cold):
        # A body with no slow path that leaves x27 and x28 alone loads the
        # next gadget's address before its body, as tcti-gadget-gen.py's
        # simple() does, so the dispatch target is known sooner.
        if cold or any(re.search(r"\b[xw]2[78]\b", line) for line in hot):
            return super().assemble(stream, hot, cold)
        return [*self.enter(stream), "ldr x27, [x28], #8", *hot, "br x27"]


# The ops and forms as the translator names them, in the table's order.
OP_NAMES = ("add", "sub", "and", "or", "xor", "cmp", "test", "adc", "sbb",
            "zero", "mov", "lea", "push", "pop", "movzxb", "movzxw", "movsxb",
            "movsxw", "movsxd", "not", "neg", "inc", "dec", "shl", "shr",
            "sar", "ror", "mul", "imul", "imul3", "bt", "bts", "btr", "btc",
            "cbw", "cwd", "xchg", "leave", "call", "jmp", "ret", "movdqa",
            "movdqu", "movsd", "movss", *(op.name for op in VFP_OPS),
            *(op.name for op in VLANE_OPS))
FORM_NAMES = ("rr", "rm", "mr", "ri", "mi", "r", "i", "m", "rri", "rmi",
              "xx", "xm", "mx")
KIND_NAMES = ("alu", "zero", "mov", "lea", "push", "pop", "extend", "unary",
              "shift", "mul", "imul3", "bt", "cbw", "cwd", "xchg", "leave",
              "call", "jmp", "ret", "vmov", "vfp", "vlane")
WORD_NAMES = ("d", "s", "s1", "base", "index", "disp", "seg", "imm", "oi",
              "tlb", "ccop")
MAX_WORDS = len(WORD_REGS)

# The gadget source files, split by op or kind so they compile in parallel;
# "other" takes the ops with no file.
# Must match target/i386/tcg/meson.build.
GADGET_FILES = ("add", "sub", "and", "or", "xor", "cmp", "test", "adc", "sbb",
                "mov", "other", "shift", "mul", "bt", "jcc", "setcc", "cmov",
                "fused", "sse", "vfp")


def op_name(spec):
    return spec.op.name if spec.op else spec.kind


def gadget_file(spec):
    if isinstance(spec, FusedSpec):
        return "fused"
    if isinstance(spec, CondSpec):
        return "jcc" if spec.kind == "jccgoto" else spec.kind
    name = op_name(spec)
    if spec.kind in ("shift", "mul", "bt"):
        return spec.kind
    if spec.kind == "vmov":
        return "sse"
    if spec.kind in ("vfp", "vlane"):
        return "vfp"
    if spec.kind == "imul3":
        return "mul"
    return name if name in GADGET_FILES else "other"


def table_index(spec, nb_shapes):
    """ Where spec is in its op and form's gadgets, which are indexed by
    width (MemOp), shape, segment base and memory order. """
    width = list(MO).index(spec.width)
    shape = EA_SHAPES.index(spec.shape) if spec.has_mem else 0
    return ((width * nb_shapes + shape) * 2 + spec.seg) * 2 + spec.ordered


def write_gadgets(outdir):
    """ Writes the gadgets, in TCTI's harness, as naked functions, and their
    table to outdir. """
    harness = TctiHarness()
    operands = ", ".join(f'[{k}] "i" ({v})' for k, v in BODY_OPERANDS.items())
    all_specs = list(specs())
    conds = list(cond_specs())
    fused = list(fused_specs())

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
    for spec in all_specs + conds + fused:
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
        write_fused_table(fused, out)

    sys.stderr.write(f"RCG: {len(all_specs) + len(conds) + len(fused)} "
                     f"gadgets with "
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
    p("static const void *const rcg_jccgoto[RCG_NB_CC][16] = {")
    for spec in conds:
        if spec.kind == "jccgoto":
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


def write_fused_table(fused, out):
    """ The fused gadgets, by setter (rcg_fused_setter, in fused_setters()'s
    order) and the Jcc's condition. """
    p = lambda *a: print(*a, file=out)
    setters = list(fused_setters())
    index = {spec.name: i for i, spec in enumerate(setters)}
    p("\n/* The gadgets a Jcc right after them can join: fused_setters(). */")
    p(f"#define RCG_NB_FUSED {len(setters)}\n")
    for spec in fused:
        p(f"void rcg_gadget_{spec.name}(void);")
    p("")
    p("static const void *const rcg_fused_setter[RCG_NB_FUSED] = {")
    for spec in setters:
        p(f"    rcg_gadget_{spec.name},")
    p("};\n")
    for kind in ("fjcc", "fjccgoto"):
        p(f"static const void *const rcg_{kind}[RCG_NB_FUSED][16] = {{")
        for spec in fused:
            if spec.kind == kind:
                p(f"    [{index[spec.setter.name]}][{spec.cond}] = "
                  f"rcg_gadget_{spec.name},")
        p("};\n")


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
    p("/* Whether a word always fits in 32 bits, signed: rcg_pack_words(). */")
    p("static inline bool rcg_word_narrow(uint8_t w)\n{\n    switch (w) {")
    for w in NARROW_WORDS:
        p(f"    case RCG_W_{w.upper()}:")
    p("        return true;\n    default:\n        return false;\n    }\n}\n")
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
    p(" * access: RCG_LOAD, RCG_STORE or both; 0 if none. reads_d: they read")
    p(" * the destination register as well as writing it.")
    p(" */")
    p("typedef struct RCGSlot {")
    p("    const RCGGadget *gadgets;")
    p("    uint8_t nb_shapes;")
    p("    uint8_t access;")
    p("    bool reads_d;")
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
    p("/* Where the translator puts CF from before an op. */")
    p("typedef enum RCGCF {")
    p("    RCG_CF_NONE,")
    p("    RCG_CF_SRC2,    /* cc_src2, before: ADC and SBB read it there */")
    p("    RCG_CF_SRC,     /* cc_src, after: INC and DEC keep it there */")
    p("} RCGCF;\n")
    p("/*")
    p(" * What the translator needs to know of an op. stack: it moves RSP.")
    p(" * branch: it ends the TB. Its gadget sets eip, except CALL rel's,")
    p(" * whose jump TCG emits. src_ot: the source's MemOp where it is not")
    p(" * the op's (MOVZX, MOVSX and MOVSXD), else -1.")
    p(" *")
    p(" * Its lazy flags. cc_op: the CC_OP it leaves, plus the width's MemOp")
    p(" * if by_width; -1 if none, and for ROR, whose CF and OF the")
    p(" * translator computes. After a shift by CL, which writes cc_op, the")
    p(" * translator records CC_OP_DYNAMIC instead, and after BT, which keeps")
    p(" * cc_dst, it adds the earlier state's MemOp. srcT: what the")
    p(" * translator puts in cc_srcT after it, as gen_SUB and gen_NEG do. dst,")
    p(" * src: whether it writes cc_dst and cc_src. cf: where the translator")
    p(" * puts CF from before it.")
    p(" */")
    p("typedef struct RCGFacts {")
    p("    RCGKind kind;")
    p("    bool stack, branch;")
    p("    int8_t src_ot;")
    p("    int cc_op;")
    p("    bool by_width;")
    p("    uint8_t srcT;")
    p("    bool dst, src;")
    p("    RCGCF cf;")
    p("} RCGFacts;\n")

    for spec in all_specs:
        p(f"void rcg_gadget_{spec.name}(void);")
    p("")

    slots = {}
    for spec in all_specs:
        slots.setdefault((op_name(spec), spec.form), []).append(spec)
    access, reads_d = {}, {}
    for (op, form), group in slots.items():
        nb_shapes = len(EA_SHAPES) if group[0].has_mem else 1
        nb_widths = max(list(MO).index(spec.width) for spec in group) + 1
        entries = [None] * (nb_widths * nb_shapes * 4)
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
        reads = {spec.reads_d for spec in group}
        assert len(reads) == 1, (op, form)
        reads_d[op, form] = str(reads.pop()).lower()
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
          f"{{ rcg_{op}_{form}, {nb_shapes}, {access[op, form]}, "
          f"{reads_d[op, form]} }},")
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
                     "RCG_SRCT_NONE" if spec.cf == "SRC" else "RCG_SRCT_ZERO"]
        elif spec.kind == "shift" and spec.op.cc:
            flags = [f"CC_OP_{spec.op.cc}B", True, "RCG_SRCT_NONE"]
        elif spec.kind in ("mul", "imul3"):
            flags = ["CC_OP_MULB", True, "RCG_SRCT_NONE"]
        elif spec.kind == "bt":
            # Plus the earlier state's MemOp, which the translator adds.
            flags = ["CC_OP_SARB", False, "RCG_SRCT_NONE"]
        else:
            flags = [-1, False, "RCG_SRCT_NONE"]
        flags += ["cc_dst" in spec.cc_writes, "cc_src" in spec.cc_writes,
                  f"RCG_CF_{spec.cf}"]
        facts = [f"RCG_KIND_{spec.kind.upper()}",
                 spec.kind in ("push", "pop", "call", "ret", "leave"),
                 spec.kind in ("call", "jmp", "ret"),
                 MO[spec.op.src] if spec.kind == "extend" else -1] + flags
        fields = ("kind", "stack", "branch", "src_ot", "cc_op", "by_width",
                  "srcT", "dst", "src", "cf")
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
    xmm says that it uses XMM0 to XMM3, which rcg-insns then compares: 1
    with the integer values, XMM_F64 or XMM_F32 with floating-point ones,
    XMM_F64N or XMM_F32N with normal ones only.
    aligned says that its access must be on a 16-byte boundary, for
    rcg-faults.
    """

    def __init__(self, insn, width, a=-1, b=-1, mem=False, base=-1,
                 index=-1, base_value=0, index_value=0, stack=False,
                 writes=False, operand=OPERAND, rsp=STACK, moved=-1,
                 target=-1, xmm=False, aligned=False):
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
        self.xmm = xmm
        self.aligned = aligned


# A case's xmm for floating-point values, doubles or floats: rcg-test.h's
# RCG_XMM_F64 and RCG_XMM_F32, and with normal values only, RCG_XMM_F64N
# and RCG_XMM_F32N.
XMM_F64 = 2
XMM_F32 = 3
XMM_F64N = 4
XMM_F32N = 5


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
    for op in MUL_OPS:
        for width in WIDTHS:
            yield from mul_cases(op, width)
    for width in IMUL3_WIDTHS:
        yield from imul3_cases(width)
    for op in BT_OPS:
        for width in BT_WIDTHS:
            yield from bt_cases(op, width)
    yield from carry_cases()
    yield from move_cases()
    yield from high_byte_cases()
    yield from addr32_cases()
    yield from vmov_cases()
    yield from scalar_vmov_cases()
    yield from vfp_cases()
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
    # A shift by CL reads RCX and the flags state.
    for setup in ("bswap rcx", "bswap rax", "add rax, rbx"):
        yield Case(f"{setup}; shl eax, cl", 64, a=0, b=3)
    # MUL reads RAX, keeps part of it at 8 bits and of RDX at 16, and
    # writes RDX above 8 bits.
    for reg in ("rax", "rdx"):
        for use in ("mul bl", "mul bx", "imul ebx", "mul rbx"):
            yield Case(f"bswap {reg}; {use}", 64, a=0, b=3)
    for setter in ("ror eax, 5", "rol rax, 3", "shl rax, cl", "imul rax, rbx",
                   "mul rbx", "bswap rax"):
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
        # AH as the source, which cannot go with REX.W.
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
    yield from shift_cl_cases(op, width)


def shift_cl_cases(op, width):
    """ Shifts by CL, with CL taking every value, so that some counts mask
    to 0: on registers and memory, and after each lazy-flags state, which a
    count of 0 keeps. """
    for n in (3, 10):
        yield Case(f"{op.name} {reg_name(n, width)}, cl", width, a=n, b=1)
    for shape in EA_SHAPES:
        for seg in SEGS:
            # The index is RSI, as RCX holds the count.
            text, base, index, bv, iv = memory_operand(width, shape, seg,
                                                       index=6)
            yield Case(f"{op.name} {text}, cl", width, b=1, mem=True,
                       base=base, index=index, base_value=bv, index_value=iv,
                       writes=True)
    if width > 8:
        for target in MISALIGNED:
            text, base, _, bv, _ = memory_operand(width, "b", None,
                                                  target=target)
            yield Case(f"{op.name} {text}, cl", width, b=1, mem=True,
                       base=base, base_value=bv, operand=target, writes=True)
    yield Case(f"{op.name} {rip_relative(width)}, cl", width, b=1, mem=True,
               writes=True)
    for setters in flag_setters(width).values():
        yield Case(f"{setters[0]}; {op.name} {reg_name(0, width)}, cl", width,
                   a=0, b=1)
    for setter in ("mov ah, 0xd5; sahf", "imul rax, rbx"):
        yield Case(f"{setter}; {op.name} {reg_name(0, width)}, cl", width,
                   b=1)
    yield Case(f"{op.name} {reg_name(1, width)}, cl", width, a=1)


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
        "sar": [f"shr {ra}, 3", f"sar {ra}, 1"],
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
    # CMP and TEST with an immediate, and of a register with itself, which
    # a Jcc right after them joins (fused_specs()); flag_setters() has them
    # with two registers.
    for width in WIDTHS:
        ra = reg_name(0, width)
        for setter in (f"cmp {ra}, 1", f"cmp {ra}, -1", f"test {ra}, -1",
                       f"test {ra}, 0x55", f"test {ra}, {ra}"):
            for cond in range(16):
                yield Case(f"{setter}; j{CONDS[cond]} 1f; mov ecx, 1; 1:",
                           width, a=0)
    # CMP and TEST with memory, by a base register and a displacement.
    for width in FUSED_MEMORY_WIDTHS:
        text, base, _, bv, _ = memory_operand(width, "b", None)
        rd = reg_name(2, width)
        for setter in (f"cmp {text}, {rd}", f"cmp {rd}, {text}",
                       f"cmp {text}, 1", f"test {text}, {rd}",
                       f"test {text}, -1"):
            for cond in range(16):
                yield Case(f"{setter}; j{CONDS[cond]} 1f; mov ecx, 1; 1:",
                           width, a=2, mem=True, base=base, base_value=bv)
        # RIP-relative, which is shape b on env's eip.
        m = rip_relative(width)
        for setter in (f"cmp {m}, {rd}", f"test {m}, -1"):
            for cond in (4, 5):
                yield Case(f"{setter}; j{CONDS[cond]} 1f; mov ecx, 1; 1:",
                           width, a=2, mem=True)
    # Registers that are not RAX and RBX, which reach a joined gadget as its
    # words, RSP among them.
    for width in WIDTHS:
        r8, r9 = reg_name(8, width), reg_name(9, width)
        for cond in (2, 4, 12):
            use = f"j{CONDS[cond]} 1f; mov ecx, 1; 1:"
            yield Case(f"cmp {r8}, {r9}; {use}", width, a=8, b=9)
            yield Case(f"cmp {r8}, 1; {use}", width, a=8)
            yield Case(f"test {r8}, {r8}; {use}", width, a=8)
    for setter in ("cmp rsp, 1", "test rsp, rsp"):
        for cond in (4, 5):
            yield Case(f"{setter}; j{CONDS[cond]} 1f; mov ecx, 1; 1:", 64,
                       stack=True)
    # A joined gadget after a TCG op, which leaves its input (BSWAP) or an
    # output of the gadget, cc_dst (XADD), in a host register.
    for setup in ("bswap rax", "xadd rax, rbx"):
        for setter in ("cmp rax, rbx", "test rax, rax"):
            yield Case(f"{setup}; {setter}; je 1f; mov ecx, 1; 1:", 64, a=0,
                       b=3)
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
    for rsp in (STACK, *MISALIGNED_STACKS):
        yield Case("mov rbp, rsp; leave", 64, stack=True, rsp=rsp)
    yield Case("lea rbp, [rsp+8]; leave", 64, stack=True)
    # A 16-bit LEAVE: TCG's.
    yield Case("mov rbp, rsp; leavew", 16, stack=True)


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
    # Loops whose body is one TB from its second pass on: the taken way goes
    # to the start of the TB, which EIP already holds, so a joined Jcc keeps
    # its plain gadget there.
    yield Case("mov ecx, 3; 1: add rax, rbx; sub ecx, 1; test ecx, ecx; "
               "jnz 1b", 64, a=0, b=3)
    yield Case("mov ecx, 0; 1: add rax, rbx; add ecx, 1; cmp ecx, 3; jb 1b",
               64, a=0, b=3)
    yield Case("mov ecx, 0; mov edx, 3; 1: add rax, rbx; add ecx, 1; "
               "cmp ecx, edx; jb 1b", 64, a=0, b=3)
    # The address size does not change what a CALL without a memory
    # operand does.
    yield Case(f"addr32 call 2f; 1: ud2; {back}; {clear}", 64, stack=True)
    yield Case(f"lea rdx, [rip+2f]; addr32 call rdx; 1: ud2; {back}; "
               f"mov edx, 0; {clear}", 64, stack=True)
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
    yield Case("lea rsi, [rip+2f]; push rsi; addr32 ret; 1: ud2; "
               "2: mov esi, 0; mov qword ptr [rsp-8], 0", 64, stack=True)


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
    # A CMP or TEST that the Jcc after it joins: the fault is the setter's.
    # The ADC start's TCG ops leave cc_src and cc_src2 in host registers, so
    # the discards after a CMP or TEST must not come before the gadget.
    for width in FUSED_MEMORY_WIDTHS:
        m, rd = f"{PTR[width]} ptr [rbx]", reg_name(2, width)
        for setter in (f"cmp {m}, {rd}", f"cmp {rd}, {m}", f"cmp {m}, 0x55",
                       f"test {m}, {rd}", f"test {m}, 0x55"):
            yield mem(f"{setter}; jne 1f; mov ecx, 1; 1:", width, a=2)
    for width in WIDTHS:
        m = f"{PTR[width]} ptr [rbx]"
        yield mem(f"mov {reg_name(0, width)}, {m}", width, a=0)
        yield mem(f"mov {m}, {reg_name(2, width)}", width, a=2, writes=True)
        yield mem(f"mov {m}, 0x55", width, writes=True)
    # AH to BH with memory.
    yield mem("mov ah, byte ptr [rbx]", 8, a=0)
    yield mem("mov byte ptr [rbx], ch", 8, a=1, writes=True)
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
    # By CL with RCX as the base: CL is the address's low byte, 0 where the
    # access starts on the upper page, a count of 0, which still writes.
    for op in SHIFT_OPS:
        for width in WIDTHS:
            yield mem(f"{op.name} {PTR[width]} ptr [rbx], cl", width,
                      writes=True)
            yield Case(f"{op.name} {PTR[width]} ptr [rcx], cl", width,
                       mem=True, base=1, moved=1, writes=True)
    # BT and friends set CF and keep ZF, and the other flags are undefined:
    # TCG leaves them differently when it translates the instruction at a
    # TB's start, as it does for the run after the fault. CF and ZF go to
    # CL and CH, then TEST defines every flag.
    for op in BT_OPS:
        for width in BT_WIDTHS:
            yield mem(f"{op.name} {PTR[width]} ptr [rbx], 5; setc cl; "
                      f"setz ch; test ecx, ecx", width, writes=op.writes)
    for op in MUL_OPS:
        for width in WIDTHS:
            yield mem(f"{op.name} {PTR[width]} ptr [rbx]", width, a=0)
    for width in IMUL3_WIDTHS:
        m = f"{PTR[width]} ptr [rbx]"
        yield mem(f"imul {reg_name(0, width)}, {m}", width, a=0)
        yield mem(f"imul {reg_name(0, width)}, {m}, 0x55", width, a=0)
    # 16 bytes: MOVDQU, which may cross the boundary, and the moves that must
    # be aligned, which run_aligned() in rcg-faults.c treats apart.
    yield mem("movdqu xmm1, xmmword ptr [rbx]", 128, xmm=True)
    yield mem("movdqu xmmword ptr [rbx], xmm2", 128, writes=True, xmm=True)
    for insn in ("movdqa", "movaps", "movapd"):
        yield mem(f"{insn} xmm1, xmmword ptr [rbx]", 128, xmm=True,
                  aligned=True)
    for insn in ("movdqa", "movaps", "movapd", "movntdq", "movntps",
                 "movntpd"):
        yield mem(f"{insn} xmmword ptr [rbx], xmm2", 128, writes=True,
                  xmm=True, aligned=True)
    # The packed floating-point ops with normal values only, which take the
    # host's FPU from the starts with PE set.
    for op in VFP_OPS:
        if op.packed:
            yield mem(f"{op.name} xmm1, {PTR[op.width]} ptr [rbx]",
                      op.width, xmm=XMM_F64N if op.lane == 64 else XMM_F32N,
                      aligned=True)
    # MOVSD and MOVSS, loads and stores, across the boundary.
    for width, insn in ((64, "movsd"), (32, "movss")):
        m = f"{PTR[width]} ptr [rbx]"
        yield mem(f"{insn} xmm1, {m}", width, xmm=True)
        yield mem(f"{insn} {m}, xmm2", width, writes=True, xmm=True)
    # The SSE floating-point ops' and the unpacks' loads, the 16-byte ones
    # aligned.
    for op in VFP_OPS + VLANE_OPS:
        yield mem(f"{op.name} xmm1, {PTR[op.width]} ptr [rbx]", op.width,
                  xmm=XMM_F64 if op.lane == 64 else XMM_F32,
                  aligned=op.width == 128)
    yield mem("push qword ptr [rbx]", 64, stack=True)
    yield mem("call qword ptr [rbx]", 64, stack=True, target=RCG_TARGET_MEM)
    yield mem("jmp qword ptr [rbx]", 64, target=RCG_TARGET_MEM)

    def stack(insn, **kw):
        return Case(insn, 64, stack=True, moved=R_ESP, **kw)

    yield stack("push rax", a=0, writes=True)
    yield stack("push 0x55", writes=True)
    yield stack("pop rax", a=0)
    yield Case("leave", 64, mem=True, base=5, moved=5)
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


def mul_cases(op, width):
    """ MUL or IMUL with one operand: RAX times a register (RAX itself and
    RDX among them) or memory, then the flags they leave as a condition
    reads them, which is TCG's. """
    for n in (3, 9, 0, 2):
        yield Case(f"{op.name} {reg_name(n, width)}", width, a=0,
                   b=n if n else -1)
    if width == 8:
        yield Case(f"{op.name} sil", 8, a=0, b=6)
        yield Case(f"{op.name} ah", 8, a=0)
    for shape in EA_SHAPES:
        for seg in SEGS:
            text, base, index, bv, iv = memory_operand(width, shape, seg)
            yield Case(f"{op.name} {text}", width, a=0, mem=True, base=base,
                       index=index, base_value=bv, index_value=iv)
    if width > 8:
        for target in MISALIGNED:
            text, base, _, bv, _ = memory_operand(width, "b", None,
                                                  target=target)
            yield Case(f"{op.name} {text}", width, a=0, mem=True, base=base,
                       base_value=bv, operand=target)
    if width >= 32:
        yield Case(f"{op.name} {PTR[width]} ptr [ebx+8]", width, a=0,
                   mem=True, base=3, base_value=ADDR32_BASE)
    yield Case(f"{op.name} {rip_relative(width)}", width, a=0, mem=True)
    # The address in RAX, which it reads, or RDX, which it writes.
    for base, a in ((0, -1), (2, 0)):
        text, _, _, bv, _ = memory_operand(width, "b", None, base=base)
        yield Case(f"{op.name} {text}", width, a=a, mem=True, base=base,
                   base_value=bv)
    for cond in range(16):
        yield Case(f"{op.name} {reg_name(3, width)}; j{CONDS[cond]} 1f; "
                   f"mov ecx, 1; 1:", width, a=0, b=3)


def imul3_cases(width):
    """ IMUL with two or three operands, then the flags it leaves as a
    condition reads them, which is TCG's. """
    yield from memory_cases("imul", width, ("rm",), False)
    text, base, _, bv, _ = memory_operand(width, "b", None)
    pairs = reg_pairs(width)
    for ra, a, rb, b in pairs:
        yield Case(f"imul {ra}, {rb}", width, a=a, b=b if b != a else -1)
    for imm in IMMS[width]:
        for ra, a, rb, b in pairs:
            yield Case(f"imul {ra}, {rb}, {imm}", width, a=a,
                       b=b if b != a else -1)
        yield Case(f"imul {reg_name(0, width)}, {text}, {imm}", width, a=0,
                   mem=True, base=base, base_value=bv)
    # The base register as the destination.
    yield Case(f"imul {reg_name(3, width)}, {text}", width, mem=True,
               base=base, base_value=bv)
    for shape in EA_SHAPES:
        for seg in SEGS:
            if shape == "b" and seg is None:
                continue
            text, base, index, bv, iv = memory_operand(width, shape, seg)
            yield Case(f"imul {reg_name(0, width)}, {text}, {-0x80}", width,
                       a=0, mem=True, base=base, index=index, base_value=bv,
                       index_value=iv)
    yield Case(f"imul {reg_name(2, width)}, {rip_relative(width)}, 3", width,
               a=2, mem=True)
    for cond in range(16):
        yield Case(f"imul {reg_name(0, width)}, {reg_name(3, width)}; "
                   f"j{CONDS[cond]} 1f; mov ecx, 1; 1:", width, a=0, b=3)


# Bit numbers for BT and friends: as the encoding takes them, before the
# mask to the operand size.
BT_BITS = (0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 255)


def bt_cases(op, width):
    """ BT, BTS, BTR or BTC by a register and by an immediate, on registers
    and memory, after each lazy-flags state, and then the flags it leaves
    as a condition reads them. After CC_OP_EFLAGS (SAHF's) and with a
    register bit number on memory, they are TCG's. """
    name = op.name
    for ra, a, rb, b in reg_pairs(width):
        yield Case(f"{name} {ra}, {rb}", width, a=a, b=b if b != a else -1)
    for n in (0, 9):
        for bit in BT_BITS:
            yield Case(f"{name} {reg_name(n, width)}, {bit}", width, a=n)
    for bit in BT_BITS:
        yield Case(f"mov edx, {bit}; {name} {reg_name(3, width)}, "
                   f"{reg_name(2, width)}", width, b=3)
    for shape in EA_SHAPES:
        for seg in SEGS:
            text, base, index, bv, iv = memory_operand(width, shape, seg)
            yield Case(f"{name} {text}, 5", width, mem=True, base=base,
                       index=index, base_value=bv, index_value=iv,
                       writes=op.writes)
    text, base, _, bv, _ = memory_operand(width, "b", None)
    for bit in BT_BITS:
        yield Case(f"{name} {text}, {bit}", width, mem=True, base=base,
                   base_value=bv, writes=op.writes)
    for target in MISALIGNED:
        text, base, _, bv, _ = memory_operand(width, "b", None, target=target)
        yield Case(f"{name} {text}, 9", width, mem=True, base=base,
                   base_value=bv, operand=target, writes=op.writes)
    yield Case(f"{name} {rip_relative(width)}, 3", width, mem=True,
               writes=op.writes)
    # A bit string in memory, by a register: TCG's. The bit number moves
    # the access, so it is kept within the operand.
    text, base, _, bv, _ = memory_operand(width, "b", None)
    yield Case(f"mov edx, 5; {name} {text}, {reg_name(2, width)}", width,
               mem=True, base=base, base_value=bv, writes=op.writes)
    ra, rb = reg_name(0, width), reg_name(3, width)
    for setters in flag_setters(width).values():
        yield Case(f"{setters[0]}; {name} {rb}, {ra}", width, a=0, b=3)
    yield Case(f"mov ah, 0xd5; sahf; {name} {rb}, {ra}", width, a=0, b=3)
    # After states the condition gadgets do not read. SBB of a register from
    # itself leaves a state at TCG's word width, whatever the operand's.
    for setter in (f"imul {ra}, {rb}", f"shl {ra}, 3", f"stc; adc {ra}, {rb}",
                   f"stc; sbb {ra}, {rb}", f"stc; sbb {ra}, {ra}"):
        yield Case(f"{setter}; {name} {rb}, {ra}; jle 1f; mov ecx, 1; 1:",
                   width, a=0, b=3)
    # After a state of another width, whose width the SAR state takes, with
    # bits above it in cc_dst and cc_src.
    for cond in range(16):
        yield Case(f"cmp al, bl; {name} {rb}, 3; j{CONDS[cond]} 1f; "
                   f"mov ecx, 1; 1:", width, a=0, b=3)
    for cond in range(16):
        yield Case(f"cmp {ra}, {rb}; {name} {rb}, 3; j{CONDS[cond]} 1f; "
                   f"mov ecx, 1; 1:", width, a=0, b=3)


def carry_cases():
    """ ADC, SBB, INC and DEC with CF from each lazy-flags state of
    flag_setters(), from SHL, MUL, ADC and SBB, and from CLC, STC, CMC and
    SAHF, which stay with TCG. A memory form follows ADC, whose state uses
    cc_src2, and CMP, whose state does not; after ADC, ADC and SBB stay with
    TCG, as the translator writes cc_src2 before a gadget that may fault.
    INC and DEC also follow a shift by CL, whose state only env has, and
    SBB of a register from itself, each state gen_compute_eflags_c() handles
    its own way. alu_cases() and unary_cases() cover the forms themselves. """
    text, base, _, bv, _ = memory_operand(64, "b", None)
    for name in ("adc", "sbb", "inc", "dec"):
        unary = name in ("inc", "dec")
        for width in (8, 64):
            ra, rb = reg_name(0, width), reg_name(3, width)
            insn = f"{name} {rb}" if unary else f"{name} {rb}, {ra}"
            setters = [s[0] for s in flag_setters(width).values()]
            setters += [f"shl {ra}, 1", f"mul {rb}", f"adc {ra}, {rb}",
                        f"sbb {ra}, {rb}"]
            if unary:
                setters += [f"shl {ra}, cl", f"sbb {ra}, {ra}"]
            for setter in setters:
                yield Case(f"{setter}; {insn}", width, a=0, b=3)
        for flag in ("clc", "stc", "cmc", "mov ah, 0xd5; sahf"):
            insn = f"{name} rbx" if unary else f"{name} rbx, rax"
            yield Case(f"{flag}; {insn}", 64, a=0, b=3)
        for setter in ("adc rax, rcx", "cmp rax, rcx"):
            insn = f"{name} {text}" if unary else f"{name} rdx, {text}"
            yield Case(f"{setter}; {insn}", 64, a=0, mem=True, base=base,
                       base_value=bv, writes=unary)


def move_cases():
    """ CBW and CWD and their wider forms, and XCHG of registers (with
    memory, it is locked, which is TCG's). """
    for name, width in (("cbw", 16), ("cwde", 32), ("cdqe", 64)):
        yield Case(name, width, a=0)
    for name, width in (("cwd", 16), ("cdq", 32), ("cqo", 64)):
        yield Case(name, width, a=0, b=2)
    for width in XCHG_WIDTHS:
        # RAX with another register has a short encoding.
        for ra, a, rb, b in reg_pairs(width):
            yield Case(f"xchg {ra}, {rb}", width, a=a, b=b if b != a else -1)
        text, base, _, bv, _ = memory_operand(width, "b", None)
        yield Case(f"xchg {text}, {reg_name(2, width)}", width, a=2, mem=True,
                   base=base, base_value=bv, writes=True)
    # Not a NOP, as 0x90 is: 87 C0, which zero-extends RAX.
    yield Case("xchg eax, eax", 32, a=0)
    # 0x90 with REX.B: the short encoding with R8.
    yield Case("xchg rax, r8", 64, a=0, b=8)


def vmov_cases():
    """ MOVDQA and MOVDQU, with MOVAPS, MOVUPS, MOVAPD and MOVUPD, which
    decode the same: between XMM registers in both encodings, and with
    memory at every operand shape and segment override and RIP-relative.
    The unaligned ones also run misaligned, as a misaligned MOVDQA raises
    #GP, which rcg-insns does not catch. """
    for insn in ("movdqa", "movdqu", "movaps", "movups", "movapd", "movupd"):
        yield Case(f"{insn} xmm1, xmm2", 128, a=0, xmm=True)
        yield Case(f"{{store}} {insn} xmm1, xmm2", 128, a=0, xmm=True)
    yield Case("movdqa xmm3, xmm3", 128, a=0, xmm=True)
    for insn in ("movdqa", "movdqu"):
        for shape in EA_SHAPES:
            for seg in SEGS:
                text, base, index, bv, iv = memory_operand(128, shape, seg)
                mem = dict(mem=True, base=base, index=index, base_value=bv,
                           index_value=iv, xmm=True)
                yield Case(f"{insn} xmm1, {text}", 128, a=0, **mem)
                yield Case(f"{insn} {text}, xmm2", 128, a=0, writes=True,
                           **mem)
        yield Case(f"{insn} xmm0, {rip_relative(128)}", 128, a=0, mem=True,
                   xmm=True)
    for target in MISALIGNED:
        text, base, _, bv, _ = memory_operand(128, "b", None, target=target)
        mem = dict(mem=True, base=base, base_value=bv, operand=target,
                   xmm=True)
        yield Case(f"movups xmm0, {text}", 128, a=0, **mem)
        yield Case(f"movdqu {text}, xmm3", 128, a=0, writes=True, **mem)
    # The same gadgets by other decodings, and XMM8 to XMM15 by way of the
    # registers the test compares.
    text, base, index, bv, iv = memory_operand(128, "b", None)
    mem = dict(mem=True, base=base, index=index, base_value=bv,
               index_value=iv, xmm=True)
    for insn in ("movaps", "movups", "movapd", "movupd", "lddqu"):
        yield Case(f"{insn} xmm1, {text}", 128, a=0, **mem)
    for insn in ("movaps", "movups", "movapd", "movupd", "movntdq",
                 "movntps", "movntpd"):
        yield Case(f"{insn} {text}, xmm2", 128, a=0, writes=True, **mem)
    yield Case("movdqa xmm8, xmm1; movdqa xmm2, xmm8", 128, a=0, xmm=True)
    yield Case("movups xmm15, xmm3; movups xmm0, xmm15", 128, a=0, xmm=True)
    yield Case(f"movdqu xmm9, {text}; movdqa xmm1, xmm9", 128, a=0, **mem)
    yield Case(f"movdqa xmm10, xmm2; movdqu {text}, xmm10", 128, a=0,
               writes=True, **mem)


def scalar_vmov_cases():
    """ MOVSD and MOVSS: between XMM registers in both encodings, which keeps
    the rest of the destination, and with memory at every operand shape and
    segment override, RIP-relative and misaligned, where a load clears it.
    MOVLPS and MOVLPD to memory store as MOVSD does, and MOVLPD between
    registers, which QEMU decodes as moving a register to itself, takes the
    MOVSD gadget. MOVNTSD and MOVNTSS need SSE4A, which the test's CPU does
    not have. """
    for width, insn in ((64, "movsd"), (32, "movss")):
        yield Case(f"{insn} xmm1, xmm2", width, a=0, xmm=True)
        yield Case(f"{{store}} {insn} xmm1, xmm2", width, a=0, xmm=True)
        yield Case(f"{insn} xmm3, xmm3", width, a=0, xmm=True)
        for shape in EA_SHAPES:
            for seg in SEGS:
                text, base, index, bv, iv = memory_operand(width, shape, seg)
                mem = dict(mem=True, base=base, index=index, base_value=bv,
                           index_value=iv, xmm=True)
                yield Case(f"{insn} xmm1, {text}", width, a=0, **mem)
                yield Case(f"{insn} {text}, xmm2", width, a=0, writes=True,
                           **mem)
        yield Case(f"{insn} xmm0, {rip_relative(width)}", width, a=0,
                   mem=True, xmm=True)
        yield Case(f"{insn} {rip_relative(width)}, xmm3", width, a=0,
                   mem=True, writes=True, xmm=True)
        for target in MISALIGNED:
            text, base, _, bv, _ = memory_operand(width, "b", None,
                                                  target=target)
            mem = dict(mem=True, base=base, base_value=bv, operand=target,
                       xmm=True)
            yield Case(f"{insn} xmm0, {text}", width, a=0, **mem)
            yield Case(f"{insn} {text}, xmm3", width, a=0, writes=True,
                       **mem)
    text, base, _, bv, _ = memory_operand(64, "b", None)
    for insn in ("movlps", "movlpd"):
        yield Case(f"{insn} {text}, xmm2", 64, a=0, mem=True, base=base,
                   base_value=bv, writes=True, xmm=True)
    yield Case(".byte 0x66, 0x0f, 0x12, 0xca", 64, a=0, xmm=True)


def vfp_cases():
    """ The SSE floating-point ops and the unpacks, between XMM registers and
    with memory at every operand shape and segment override and
    RIP-relative, over the floating-point values, and with XMM9, XMM10 and
    XMM12, which need REX, copied from and to the registers the test loads.
    XMM2 then takes XMM3's value, so that reading XMM2 for XMM10 would show.
    b, which nothing reads, makes the cases without memory take every pair
    of values. The packed floating-point ops also run with normal values
    only, whose lanes can take the host's FPU (for SQRT, the positive ones).
    The test's CPU has no AVX, so there are no VEX encodings, which RCG
    leaves to TCG. """
    for op in VFP_OPS + VLANE_OPS:
        xmm = XMM_F64 if op.lane == 64 else XMM_F32
        width = op.width
        yield Case(f"{op.name} xmm1, xmm2", width, a=0, b=1, xmm=xmm)
        yield Case(f"{op.name} xmm3, xmm3", width, a=0, xmm=xmm)
        yield Case(f"movaps xmm9, xmm1; movaps xmm10, xmm2; "
                   f"movaps xmm2, xmm3; {op.name} xmm9, xmm10; "
                   f"movaps xmm1, xmm9", width, a=0, b=1, xmm=xmm)
        text, base, index, bv, iv = memory_operand(width, "bi1", None)
        yield Case(f"movaps xmm12, xmm1; {op.name} xmm12, {text}; "
                   f"movaps xmm1, xmm12", width, a=0, mem=True, base=base,
                   index=index, base_value=bv, index_value=iv, xmm=xmm)
        for shape in EA_SHAPES:
            for seg in SEGS:
                text, base, index, bv, iv = memory_operand(width, shape, seg)
                yield Case(f"{op.name} xmm1, {text}", width, a=0, mem=True,
                           base=base, index=index, base_value=bv,
                           index_value=iv, xmm=xmm)
        yield Case(f"{op.name} xmm0, {rip_relative(width)}", width, a=0,
                   mem=True, xmm=xmm)
        if isinstance(op, VFp) and op.packed:
            n = XMM_F64N if op.lane == 64 else XMM_F32N
            text, base, index, bv, iv = memory_operand(width, "b", None)
            yield Case(f"{op.name} xmm1, xmm2", width, a=0, b=1, xmm=n)
            yield Case(f"{op.name} xmm1, {text}", width, a=0, mem=True,
                       base=base, index=index, base_value=bv,
                       index_value=iv, xmm=n)


def addr32_cases():
    """ Instructions with the 32-bit address size and no memory operand,
    where it changes nothing. With one, they stay with TCG (see
    memory_cases()). CALL and RET are in branch_cases(). """
    for insn, a, b, stack in (
            ("addr32 add rax, rbx", 0, 3, False),
            ("addr32 mov ecx, edx", 1, 2, False),
            ("addr32 push rax", 0, -1, True),
            ("addr32 pop rcx", 1, -1, True),
            ("addr32 imul eax, ebx, 5", 0, 3, False),
            ("cmp eax, ebx; addr32 setb cl", 0, 3, False),
            ("cmp eax, ebx; addr32 jb 1f; mov ecx, 1; 1:", 0, 3, False),
            ("mov rbp, rsp; addr32 leave", -1, -1, True)):
        yield Case(insn, 64, a=a, b=b, stack=stack)


def high_byte_cases():
    """ AH, CH, DH and BH with the instructions whose gadgets take them,
    which use no more of an 8-bit register than its low byte: MOV, MOVZX,
    MOVSX, XCHG, MUL, IMUL and SETcc. Those left to TCG are in
    alu_cases(), shift_cases() and so on. Some share RAX with an operand
    the instruction reads or writes without naming it. """
    text, base, _, bv, _ = memory_operand(8, "b", None)
    for insn, a, b in (("mov ah, bh", 0, 3), ("mov ch, al", 1, 0),
                       ("mov dh, 0x7f", 2, -1), ("xchg ah, al", 0, -1),
                       ("xchg ah, ah", 0, -1), ("xchg ch, bl", 1, 3),
                       ("xchg bh, dh", 3, 2), ("movzx eax, ah", 0, -1),
                       ("movzx ecx, bh", 1, 3), ("movzx dx, ch", 2, 1),
                       ("movsx eax, dh", 0, 2), ("movsx ebx, ah", 3, 0),
                       ("movsx cx, bh", 1, 3), ("mul ch", 0, 1),
                       ("mul ah", 0, -1), ("imul bh", 0, 3),
                       ("imul ah", 0, -1)):
        yield Case(insn, 8, a=a, b=b)
    for insn, a, writes in ((f"mov ah, {text}", 0, False),
                            (f"mov {text}, ch", 1, True)):
        yield Case(insn, 8, a=a, mem=True, base=base, base_value=bv,
                   writes=writes)
    for cond in range(16):
        yield Case(f"cmp eax, ebx; set{CONDS[cond]} bh", 32, a=0, b=3)
        yield Case(f"cmp eax, ebx; set{CONDS[cond]} ah", 32, a=0, b=3)


def write_cases(cases, out, prefix, adc=False):
    """ The cases as rcg-test.h's RCG_CASE() macros, one per case, which
    make the functions that run the instruction, then a table of the
    cases. adc adds RCG_ADC_CASE()'s function, which runs the instruction
    after an ADC. """
    cases = list(cases)
    print("/* Automatically generated by rcg-gen.py. Do not edit. */\n",
          file=out)
    for i, c in enumerate(cases):
        print(f'RCG_CASE({prefix}{i}, "{c.insn}", {int(c.xmm)})', file=out)
        if adc:
            print(f'RCG_ADC_CASE({prefix}{i}, "{c.insn}", {int(c.xmm)})',
                  file=out)
    print(f"\nstatic const struct rcg_case {prefix}cases[] = {{", file=out)
    for i, c in enumerate(cases):
        name = f"{prefix}{i}"
        if adc:
            fn_adc = f"{name}_adc, {name}_adc_insn, {name}_adc_end"
        else:
            fn_adc = "NULL, NULL, NULL"
        print(f'    {{ "{c.insn}", {name}, {name}_insn, {name}_end, '
              f'{name}_sub, {name}_sub_insn, {name}_sub_end, {fn_adc}, '
              f'{c.width}, {c.a}, {c.b}, {int(c.mem)}, {c.base}, '
              f'{c.index}, {c.base_value:#x}, {c.index_value}, '
              f'{int(c.stack)}, {int(c.writes)}, {c.operand:#x}, {c.rsp:#x}, '
              f'{c.moved}, {c.target}, {int(c.xmm)}, {int(c.aligned)} }},',
              file=out)
    print("};", file=out)


def jcc_cases():
    """ The cases of rcg-jcc: rcg-insns' cases that end in a Jcc forward.
    Its Makefile rule finds their hashes in rcg-insns.ref the same way. """
    return (c for c in insn_cases()
            if re.search(r"(^|; )j[a-z]+ 1f; mov ecx, 1; 1:$", c.insn))


def jcc_fault_cases():
    """ The cases of rcg-faults-jcc: rcg-faults' cases that end in a Jcc
    forward. """
    return (c for c in fault_cases()
            if re.search(r"(^|; )j[a-z]+ 1f; mov ecx, 1; 1:$", c.insn))


def check_coverage(order, nm, traces):
    """ Checks that the rcg_insn and rcg_jumps trace events in traces, from
    runs of QEMU's x86_64 system emulator, took every gadget that the
    translator or TCTI can pick under order: "ordered" where
    tcg_ldst_ordered() holds, which picks the ordered twins, else "plain".
    nm is nm's listing of that
    QEMU, from which each trace's ASLR slide is found. The events come at
    translation, so this says that each gadget was picked, not that it
    ran. Also checks that a Jcc right after a setter it can join took a
    fused gadget, which the tests' hashes cannot show. Returns whether both
    hold. """
    names = {}
    for line in open(nm):
        parts = line.split()
        if len(parts) == 3 and parts[2].lstrip("_").startswith("rcg_gadget_"):
            names[int(parts[0], 16)] = parts[2].lstrip("_")[11:]
    taken = set()
    # What a setter's Jcc would be called. A Jcc of another state ran after
    # a TCG instruction, which the trace does not show, set the flags again.
    setters = {spec.name: (f"jcc_{'sub' if spec.op.cc == 'SUB' else 'logic'}"
                           f"{spec.width}_")
               for spec in fused_setters()}
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
            for spec in [*specs(), *cond_specs(), *fused_specs()]
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


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--insn-tests", metavar="FILE",
                        help="write rcg-insns.c's cases to FILE")
    parser.add_argument("--jcc-tests", metavar="FILE",
                        help="write rcg-jcc.c's cases to FILE")
    parser.add_argument("--jcc-fault-tests", metavar="FILE",
                        help="write rcg-faults-jcc's cases to FILE")
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
    if not (args.insn_tests or args.jcc_tests or args.fault_tests or
            args.jcc_fault_tests or args.check or args.gadgets or
            args.coverage):
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
    if args.jcc_tests:
        with open(args.jcc_tests, "w") as out:
            write_cases(jcc_cases(), out, "rcg_insn_")
    if args.fault_tests:
        with open(args.fault_tests, "w") as out:
            write_cases(fault_cases(), out, "rcg_fault_", adc=True)
    if args.jcc_fault_tests:
        with open(args.jcc_fault_tests, "w") as out:
            write_cases(jcc_fault_cases(), out, "rcg_fault_", adc=True)
    if args.coverage:
        order, nm, *traces = args.coverage
        if not check_coverage(order, nm, traces):
            sys.exit(1)


if __name__ == "__main__":
    main()
