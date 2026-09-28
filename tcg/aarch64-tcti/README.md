# QEMU Tiny-Code Threaded Interpreter (AArch64)

A TCG backend that chains together JOP/ROP-ish gadgets to massively reduce interpreter overhead vs TCI.
Platform-dependent; but usable when JIT isn't available; e.g. on platforms that lack WX mappings. The general idea squish the addresses of a gadget sequence into a "queue" and then write each gadget so it ends in a "dequeue-jump".

Execution occurs by jumping into the first gadget, and letting it just play back some linear-overhead native code sequences for a while.

Since TCG-TCI is optimized for sets of 16 GP registers and aarch64 has 30, we could easily keep JIT/QEMU and guest state separate, and since 16\*16 is reasonably small we could actually have a set of reasonable gadgets for each combination of operands.


## Register Convention

| Regs    | Use                   |
| :------ | :-------------------- |
| x1-x15  | Guest Registers       |
| x24     | TCTI temporary        |
| x25     | saved IP during call  |
| x26     | TCTI temporary        |
| x27     | TCTI temporary        |
| x28     | Thread-stream pointer |
| x30     | Link register         |
| SP      | Stack Pointer, host   |
| PC      | Program Counter, host |

In pseudocode:

| Symbol | Meaning                             |
| :----- | :---------------------------------- |
| Rd     | stand-in for destination register   |
| Rn     | stand-in for first source register  |
| Rm     | stand-in for second source register |

## Gadget Structure

### End of gadget

Each gadget ends by advancing our bytecode pointer, and then executing from thew new location.

```asm
# Load our next gadget address from our bytecode stream, advancing it, and jump to the next gadget.

ldr x27, [x28], #8\n
br x27
```

## Calling into QEMU's C codebase

When calling into C, we lose control over which registers are used. Accordingly, we'll need to save
registers relevant to TCTI:

```asm
str x25,      [sp, #-16]!
stp x14, x15, [sp, #-16]!
stp x12, x13, [sp, #-16]!
stp x10, x11, [sp, #-16]!
stp x8,  x9,  [sp, #-16]!
stp x6,  x7,  [sp, #-16]!
stp x4,  x5,  [sp, #-16]!
stp x2,  x3,  [sp, #-16]!
stp x0,  x1,  [sp, #-16]!
stp x28, lr,  [sp, #-16]!
```

Upon returning to the gadget stream, we'll then restore them.

```asm
ldp x28, lr, [sp], #16
ldp x0,  x1, [sp], #16
ldp x2,  x3, [sp], #16
ldp x4,  x5, [sp], #16
ldp x6,  x7, [sp], #16
ldp x8,  x9, [sp], #16
ldp x10, x11, [sp], #16
ldp x12, x13, [sp], #16
ldp x14, x15, [sp], #16
ldr x25,      [sp], #16
```

## TCG Operations

Each operation needs an implementation for every platform; and probably a set of gadgets for each possible set of operands.

At 14 GP registers, that means that

1 operand =\> 16 gadgets
2 operands =\> 256 gadgets
3 operands =\> 4096 gadgets

### call

Calls a helper function by address.

**IR Format**: `br <ptr address>`  
**Gadget type:** single

```asm
    # Get our C runtime function's location as a pointer-sized immediate...
    "ldr x27, [x28], #8",

    # Store our TB return address for our helper. This is necessary so the GETPC()
    # macro works correctly as used in helper functions.
    "str x28, [x25]",

    # Prepare ourselves to call into our C runtime...
    *C_CALL_PROLOGUE,

    # ... perform the call itself ...
    "blr x27",

    # Save the result of our call for later.
    "mov x27, x0",

    # ... and restore our environment.
    *C_CALL_EPILOGUE,

    # Restore our return value.
    "mov x0, x27"
```

### br

Branches to a given immediate address. Branches are

**IR Format**: `br <ptr address>`  
**Gadget type:** single

```asm
# Use our immediate argument as our new bytecode-pointer location.
ldr x28, [x28]
```

### setcond_i32

Performs a comparison between two 32-bit operands.

**IR Format**: `setcond32 <cond>, Rd, Rn, Rm`  
**Gadget type:** treated as 10 operations with variants for every `Rd`/`Rn`/`Rm` (40,960)

```asm
subs Wd, Wn, Wm
cset Wd, <cond>
```

| QEMU Cond | AArch64 Cond |
| :-------- | :----------- |
| EQ        | EQ           |
| NE        | NE           |
| LT        | LT           |
| GE        | GE           |
| LE        | LE           |
| GT        | GT           |
| LTU       | LO           |
| GEU       | HS           |
| LEU       | LS           |
| GTU       | HI           |

### setcond_i64

Performs a comparison between two 32-bit operands.

**IR Format**: `setcond64 <cond>, Rd, Rn, Rm`  
**Gadget type:** treated as 10 operations with variants for every `Rd`/`Rn`/`Rm` (40,960)

```asm
subs Xd, Xn, Xm
cset Xd, <cond>
```

Comparison chart is the same as the `_i32` variant.

### brcond_i32

Compares two 32-bit numbers, and branches if the comparison is true.

**IR Format**: `brcond Rn, Rm, <cond>`  
**Gadget type:** treated as 10 operations with variants for every `Rn`/`Rm` (2560)

```asm
# Perform our comparison and conditional branch.
subs Wrz, Wn, Wm
br<cond> taken

    # Consume the branch target, without using it.
    add x28, x28, #8

    # Perform our end-of-instruction epilogue.
    <epilogue here>

taken:

    # Update our bytecode pointer to take the label.
    ldr x28, [x28]
```

Comparison chart is the same as in `setcond_i32` .

### brcond_i64

Compares two 64-bit numbers, and branches if the comparison is true.

**IR Format**: `brcond Rn, Rm, <cond>`  
**Gadget type:** treated as 10 operations with variants for every `Rn`/`Rm` (2560)

```asm
# Perform our comparison and conditional branch.
subs Xrz, Xn, Xm
br<cond> taken

    # Consume the branch target, without using it.
    add x28, x28, #8

    # Perform our end-of-instruction epilogue.
    <epilogue here>

taken:

    # Update our bytecode pointer to take the label.
    ldr x28, [x28]
```

Comparison chart is the same as in `setcond_i32` .

### mov_i32

Moves a value from a register to another register.

**IR Format**: `mov Rd, Rn`  
**Gadget type:** gadget per `Rd` + `Rn` combo (256)

```asm
mov Rd, Rn
```

### mov_i64

Moves a value from a register to another register.

**IR Format**: `mov Rd, Rn`  
**Gadget type:** gadget per `Rd` + `Rn` combo (256)

```asm
mov Xd, Xn
```

### tci_movi_i32

Moves an 32b immediate into a register.

**IR Format**: `mov Rd, #imm32`  
**Gadget type:** gadget per `Rd` (16)

```asm
ldr w27, [x28], #4
mov Wd, w27
```

### tci_movi_i64

Moves an 64b immediate into a register.

**IR Format**: `mov Rd, #imm64`  
**Gadget type:** gadget per `Rd` (16)

```asm
ldr x27, [x28], #4
mov Xd, x27
```

### ld8u_i32 / ld8u_i64

Load byte from host memory to register.

**IR Format**: `ldr Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
ldrb Xd, [Xn, x27]
```

### ld8s_i32 / ld8s_i64

Load byte from host memory to register; sign extending.

**IR Format**: `ldr Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
ldrsb Xd, [Xn, x27]
```

### ld16u_i32 / ld16u_i64

Load 16b from host memory to register.

**IR Format**: `ldr Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
ldrh Wd, [Xn, x27]
```

### ld16s_i32 / ld16s_i64

Load 16b from host memory to register; sign extending.

**IR Format**: `ldr Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
ldrsh Xd, [Xn, x27]
```

### ld32u_i32 / ld32u_i64

Load 32b from host memory to register.

**IR Format**: `ldr Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
ldr Wd, [Xn, x27]
```

### ld32s_i64

Load 32b from host memory to register; sign extending.

**IR Format**: `ldr Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
ldrsw Xd, [Xn, x27]
```

### ld_i64

Load 64b from host memory to register.

**IR Format**: `ldr Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
ldr Xd, [Xn, x27]
```

### st8_i32 / st8_i64

Stores byte from register to host memory.

**IR Format**: `str Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
strb Wd, [Xn, x27]
```

### st16_i32 / st16_i64

Stores 16b from register to host memory.

**IR Format**: `str Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
strh Wd, [Xn, x27]
```

### st_i32 / st32_i64

Stores 32b from register to host memory.

**IR Format**: `str Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
str Wd, [Xn, x27]
```

### st_i64

Stores 64b from register to host memory.

**IR Format**: `str Rd, Rn, <signed offset>`  
**Gadget type:** gadget per `Rd` & `Rn` (256)

```asm
ldrsw x27, [x28], #4
str Xd, [Xn, x27]
```

### qemu_ld_i32

Loads 32b from _guest_ memory to register.

**IR Format**: `ld Rd, <foreign/guest pointer>, <memory operation>`  
**Gadget type:** thunk per `Rd` into C impl?

### qemu_ld_i64

Loads 64b from _guest_ memory to register.

**IR Format**: `ld Rd, <foreign/guest pointer>, <memory operation>`  
**Gadget type:** thunk per `Rd` into C impl?

### qemu_st_i32

Stores 32b from a register to _guest_ memory.

**IR Format**: `st Rd, <foreign/guest pointer>, <memory operation>`  
**Gadget type:** thunk per `Rd` into C impl

### qemu_st_i64

Stores 64b from a register to _guest_ memory.

**IR Format**: `st Rd, <foreign/guest pointer>, <memory operation>`  
**Gadget type:** thunk per `Rd` into C impl?

#### Note

See note on `qemu_ld_i32`.

### add_i32

Adds two 32-bit numbers.

**IR Format**: `add Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
add Wd, Wn, Wm
```

### add_i64

Adds two 64-bit numbers.

**IR Format**: `add Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
add Xd, Xn, Xm
```

### sub_i32

Subtracts two 32-bit numbers.

**IR Format**: `add Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
Sub Wd, Wn, Wm
```

### sub_i64

Subtracts two 64-bit numbers.

**IR Format**: `sub Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
sub Xd, Xn, Xm
```

### mul_i32

Multiplies two 32-bit numbers.

**IR Format**: `mul Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
mul Wd, Wn, Wm
```

### mul_i64

Multiplies two 64-bit numbers.

**IR Format**: `mul Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
mul Xd, Xn, Xm
```

### div_i32

Divides two 32-bit numbers; considering them signed.

**IR Format**: `div Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
sdiv Wd, Wn, Wm
```

### div_i64

Divides two 64-bit numbers; considering them signed.

**IR Format**: `div Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
sdiv Xd, Xn, Xm
```

### divu_i32

Divides two 32-bit numbers; considering them unsigned.

**IR Format**: `div Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
udiv Wd, Wn, Wm
```

### divu_i64

Divides two 32-bit numbers; considering them unsigned.

**IR Format**: `div Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
udiv Xd, Xn, Xm
```

### rem_i32

Computes the division remainder (modulus) of two 32-bit numbers; considering them signed.

**IR Format**: `rem Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
sdiv    w27, Wn, Wm
msub    Wd, w27, Wm, Wn
```

### rem_i64

Computes the division remainder (modulus) of two 64-bit numbers; considering them signed.

**IR Format**: `rem Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
sdiv    x27, Xn, Xm
msub    Xd, x27, Xm, Xn
```

### remu_i32

Computes the division remainder (modulus) of two 32-bit numbers; considering them unsigned.

**IR Format**: `rem Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
udiv    w27, Wn, Wm
msub    Wd, w27, Wm, Wn
```

### remu_i64

Computes the division remainder (modulus) of two 32-bit numbers; considering them unsigned.

**IR Format**: `rem Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
udiv    x27, Xn, Xm
msub    Xd, x27, Xm, Xn
```

### not_i32

Logically inverts a 32-bit number.

**IR Format**: `not Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
mvn Wd, Wn
```

### not_i64

Logically inverts a 64-bit number.

**IR Format**: `not Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
mvn Xd, Xn
```

### neg_i32

Arithmetically inverts (two's compliment) a 32-bit number.

**IR Format**: `not Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
neg Wd, Wn
```

### neg_i64

Arithmetically inverts (two's compliment) a 64-bit number.

**IR Format**: `not Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
neg Xd, Xn
```

### and_i32

Logically ANDs two 32-bit numbers.

**IR Format**: `and Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
and Wd, Wn, Wm
```

### and_i64

Logically ANDs two 64-bit numbers.

**IR Format**: `and Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
and Xd, Xn, Xm
```

### or_i32

Logically ORs two 32-bit numbers.

**IR Format**: `or Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
or Wd, Wn, Wm
```

### or_i64

Logically ORs two 64-bit numbers.

**IR Format**: `or Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
or Xd, Xn, Xm
```

### xor_i32

Logically XORs two 32-bit numbers.

**IR Format**: `xor Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
eor Wd, Wn, Wm
```

### xor_i64

Logically XORs two 64-bit numbers.

**IR Format**: `xor Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
eor Xd, Xn, Xm
```

### shl_i32

Logically shifts a 32-bit number left.

**IR Format**: `shl Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
lsl Wd, Wn, Wm
```

### shl_i64

Logically shifts a 64-bit number left.

**IR Format**: `shl Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
lsl Xd, Xn, Xm
```

### shr_i32

Logically shifts a 32-bit number right.

**IR Format**: `shr Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
lsr Wd, Wn, Wm
```

### shr_i64

Logically shifts a 64-bit number right.

**IR Format**: `shr Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
lsr Xd, Xn, Xm
```

### sar_i32

Arithmetically shifts a 32-bit number right.

**IR Format**: `sar Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
asr Wd, Wn, Wm
```

### sar_i64

Arithmetically shifts a 64-bit number right.

**IR Format**: `sar Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
asr Xd, Xn, Xm
```

### rotl_i32

Rotates a 32-bit number left.

**IR Format**: `rotl Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
rol Wd, Wn, Wm
```

### rotl_i64

Rotates a 64-bit number left.

**IR Format**: `rotl Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
rol Xd, Xn, Xm
```

### rotr_i32

Rotates a 32-bit number right.

**IR Format**: `rotr Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
ror Wd, Wn, Wm
```

### rotr_i64

Rotates a 64-bit number right.

**IR Format**: `rotr Rd, Rn, Rm`  
**Gadget type:** gadget per `Rd`, `Rn`, `Rm` (4096)

```asm
ror Xd, Xn, Xm
```

### deposit_i32

Optional; not currently implementing.

### deposit_i64

Optional; not currently implementing.

### ext8s_i32

Sign extends the lower 8b of a register into a 32b destination.

**IR Format**: `ext8s Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
sxtb Wd, Wn
```

### ext8s_i64

Sign extends the lower 8b of a register into a 64b destination.

**IR Format**: `ext8s Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
sxtb Xd, Wn
```

### ext8u_i32

Zero extends the lower 8b of a register into a 32b destination.

**IR Format**: `ext8u Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
and Xd, Xn, #0xff
```

### ext8u_i64

Zero extends the lower 8b of a register into a 64b destination.

**IR Format**: `ext8u Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
and Xd, Xn, #0xff
```

### ext16s_i32

Sign extends the lower 16b of a register into a 32b destination.

**IR Format**: `ext16s Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
sxth Xd, Wn
```

### ext16s_i64

Sign extends the lower 16b of a register into a 64b destination.

**IR Format**: `ext16s Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
sxth Xd, Wn
```

### ext16u_i32

Zero extends the lower 16b of a register into a 32b destination.

**IR Format**: `ext16u Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
and Wd, Wn, #0xffff
```

### ext16u_i64

Zero extends the lower 16b of a register into a 32b destination.

**IR Format**: `ext16u Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
and Wd, Wn, #0xffff
```

### ext32s_i64

Sign extends the lower 32b of a register into a 64b destination.

**IR Format**: `ext32s Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
sxtw Xd, Wn
```

### ext32u_i64

Zero extends the lower 32b of a register into a 64b destination.

**IR Format**: `ext32s Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
sxtw Xd, Wn
```

### ext_i32_i64

Sign extends the lower 32b of a register into a 64b destination.

**IR Format**: `ext32s Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
sxtw Xd, Wn
```

### extu_i32_i64

Zero extends the lower 32b of a register into a 32b destination.

**IR Format**: `ext32u Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
and Xd, Xn, #0xffffffff
```

### bswap16_i32

Byte-swaps a 16b quantity.

**IR Format**: `bswap16 Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
rev     w27, Wn
lsr     Wd, w27, #16
```

### bswap16_i64

Byte-swaps a 16b quantity.

**IR Format**: `bswap16 Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
rev     w27, Wn
lsr     Wd, w27, #16
```

### bswap32_i32

Byte-swaps a 32b quantity.

**IR Format**: `bswap32 Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
rev     Wd, Wn
```

### bswap32_i64

Byte-swaps a 32b quantity.

**IR Format**: `bswap32 Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
rev     Wd, Wn
```

### bswap64_i64

Byte-swaps a 64b quantity.

**IR Format**: `bswap64 Rd, Rn`  
**Gadget type:** gadget per `Rd`, `Rn` (256)

```asm
rev     Xd, Xn
```

### exit_tb

Exits the translation block. Has no gadget; but instead inserts the address of the translation block epilogue.


### mb

Memory barrier.

**IR Format**: `mb <type>`  
**Gadget type:** gadget per type

```asm
# !!! TODO
```

#### Note

We still need to look up out how to map QEMU MB types map to AArch64 ones. This might take nuance.
