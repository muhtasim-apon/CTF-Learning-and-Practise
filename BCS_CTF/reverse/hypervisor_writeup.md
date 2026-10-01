# Nested VM (Hypervisor) — Reverse Engineering Writeup

**Challenge:** Nested VM (Hypervisor) · Author: otolk1 · Difficulty: Hard
**Flag format:** `bcsctf{...}`

## Flag

```
bcsctf{vms_w1th1n_vms_4ll_th3_w4y_d0wn_a39f1c}
```

Verified against the real binary:

```
$ echo 'bcsctf{vms_w1th1n_vms_4ll_th3_w4y_d0wn_a39f1c}' | ./challenge
=== BCS CTF: Hypervisor Challenge ===
Enter flag:
[+] Access Granted! Flag verified successfully.
```

---

## 1. Triage

```
$ file challenge
challenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
           dynamically linked, for GNU/Linux 3.2.0, stripped
$ file challenge_vm.bin
challenge_vm.bin: data   (10496 bytes = 0x2900)
```

`strings` yields only the UI text — no crypto constants, no flag fragments:

```
=== BCS CTF: Hypervisor Challenge ===
[+] Access Granted! Flag verified successfully.
[-] Access Denied! Invalid flag.
Enter flag:
Error reading input.
```

Section layout (`readelf -S -W`):

| Section   | VAddr      | Off      | Size     |
|-----------|------------|----------|----------|
| `.text`   | `0x4010c0` | `0x10c0` | `0x8c7`  |
| `.rodata` | `0x402000` | `0x2000` | `0x2acd` |
| `.bss`    | `0x406060` | —        | `0x10040`|

`.text` is tiny (2247 bytes) while `.rodata` is 10.9 KB and `.bss` is 64 KiB. That ratio is
the tell: the logic is not x86, it is *data* interpreted by a small engine, with a 64 KiB
guest RAM reserved for it.

## 2. `main` — how the VM is set up

`main` is at `0x4010e0`, found via the `mov rdi, 0x4010e0` handed to `__libc_start_main`
at `0x401274`:

```asm
4010e0: sub    rsp,0x118
4010e7: xor    esi,esi
4010e9: mov    edx,0x10000
4010ee: mov    edi,0x4060a0
4010f3: call   memset          ; VM RAM = 64 KiB at .bss+0x40, zeroed
4010f8: mov    edx,0x2900
4010fd: mov    esi,0x402120
401102: mov    edi,0x4060a0
401107: call   memcpy          ; copy 0x2900 bytes of .rodata to VM address 0x0000
...
40113f: call   fgets           ; read up to 0x100 bytes
401152: call   strlen          ; strip trailing \n / \r
401187: mov    edi,0x40a0a0    ; == 0x4060a0 + 0x4000  ->  VM address 0x4000
...     (inline SSE + byte-loop copy of the input into VM RAM)
4011af: mov    edi,0x4060a0
4011b4: call   0x401350        ; <-- the VM interpreter
4011b9: test   eax,eax
4011bb: jne    .denied         ; return value 0 == Access Granted
```

Three facts fall out:

* **VM RAM** = 64 KiB at `0x4060a0`, fully zeroed first.
* **VM ROM** = `.rodata+0x120` (`0x402120`), `0x2900` bytes, mapped at VM address `0`.
  A byte-compare confirms this blob **is exactly `challenge_vm.bin`** — the provided
  `.bin` is redundant, the firmware is already embedded in the ELF.
* **Input** is placed at VM address `0x4000`, NUL-terminated.

```python
d = open('challenge','rb').read()
assert d[0x2120:0x2120+0x2900] == open('challenge_vm.bin','rb').read()   # True
```

## 3. Level 1 — the x86 interpreter (16-bit register machine)

`0x401350` is a classic table-dispatch loop:

```asm
401350: pxor   xmm0,xmm0
401354: xor    r10d,r10d        ; CF
401357: xor    r9d,r9d          ; ZF
40135a: mov    r8d,0x7ffe       ; SP
401360: movaps XMMWORD PTR [rsp-0x18],xmm0   ; R0..R7 = 0  (8 x uint16)
401365: xor    esi,esi          ; PC = 0
401370: movzx  edx,si
401373: lea    eax,[rsi+1]
401376: cmp    BYTE PTR [rdi+rdx*1],0x1f
40137a: ja     0x4010c0         ; opcode > 0x1f -> return 0xffffffff
401380: movzx  edx,BYTE PTR [rdi+rdx*1]
401384: jmp    QWORD PTR [rdx*8+0x402020]    ; 32-entry jump table in .rodata
```

**Machine model**

| Item      | Encoding                                                     |
|-----------|--------------------------------------------------------------|
| Registers | `R0..R7`, 16-bit, held at `[rsp-0x18]`, zeroed by the `movaps` |
| PC        | `esi`, 16-bit wrap                                            |
| SP        | `r8d`, starts `0x7ffe`, full-descending, 2-byte slots         |
| ZF        | `r9b`                                                         |
| CF        | `r10b`, set by `setb` — unsigned "below"                      |
| Memory    | `rdi`, 64 KiB flat, little-endian words                       |
| Reg field | every register operand byte is masked `& 7`                   |

The jump table at `.rodata+0x20` (`0x402020`) decodes to:

```
op 00 -> 0x4013d0   op 08 -> 0x401940   op 10 -> 0x401658   op 18 -> 0x4014b0
op 01 -> 0x4016b0   op 09 -> 0x401908   op 11 -> 0x401610   op 19 -> 0x401470
op 02 -> 0x401710   op 0a -> 0x4018c8   op 12 -> 0x4015e0   op 1a -> 0x401430
op 03 -> 0x4016d8   op 0b -> 0x401890   op 13 -> 0x4015b0   op 1b -> 0x401410
op 04 -> 0x4017b0   op 0c -> 0x401860   op 14 -> 0x401580   op 1c -> 0x401400
op 05 -> 0x401790   op 0d -> 0x401828   op 15 -> 0x401548   op 1d -> 0x4013d8
op 06 -> 0x401770   op 0e -> 0x4017f0   op 16 -> 0x401510   op 1e -> 0x4016a0
op 07 -> 0x401740   op 0f -> 0x4017c0   op 17 -> 0x4014e0   op 1f -> 0x401390
```

### Recovered L1 instruction set

| Op | Mnemonic | Len | Semantics |
|----|----------|-----|-----------|
| 00 | `NOP` | 1 | — |
| 01 | `RET` | 1 | `PC = [SP]; SP += 2` |
| 02 | `PUSH Ra` | 2 | `SP -= 2; [SP] = Ra` |
| 03 | `POP Ra` | 2 | `Ra = [SP]; SP += 2` |
| 04 | `HLT Ra` | 2 | return `Ra` to the x86 caller |
| 05 | `INC Ra` | 2 | `Ra++` |
| 06 | `DEC Ra` | 2 | `Ra--` |
| 07 | `MOVI Ra,imm16` | 4 | `Ra = imm` |
| 08 | `ADDI Ra,imm16` | 4 | `Ra += imm`, ZF |
| 09 | `SUBI Ra,imm16` | 4 | `Ra -= imm`, ZF |
| 0a | `CMPI Ra,imm16` | 4 | ZF, CF |
| 0b | `ANDI Ra,imm16` | 4 | `Ra &= imm`, ZF |
| 0c | `MOV Ra,Rb` | 3 | |
| 0d | `ADD Ra,Rb` | 3 | ZF |
| 0e | `SUB Ra,Rb` | 3 | ZF |
| 0f | `MUL Ra,Rb` | 3 | 16-bit truncating |
| 10 | `DIV Ra,Rb` | 3 | `Rb == 0 -> Ra = 0` |
| 11 | `MOD Ra,Rb` | 3 | `Rb == 0 -> Ra = 0` |
| 12 | `XOR Ra,Rb` | 3 | |
| 13 | `AND Ra,Rb` | 3 | |
| 14 | `OR Ra,Rb` | 3 | |
| 15 | `CMP Ra,Rb` | 3 | ZF, CF |
| 16 | `ROL8 Ra,Rb` | 3 | `Ra = rol8(Ra & 0xff, Rb & 7)` |
| 17 | `LDB Ra,[Rb]` | 3 | zero-extended byte load |
| 18 | `STB [Ra],Rb` | 3 | byte store |
| 19 | `LDW Ra,[Rb]` | 3 | LE word load |
| 1a | `STW [Ra],Rb` | 3 | LE word store |
| 1b | `JMP imm16` | 3 | |
| 1c | `JZ imm16` | 3 | |
| 1d | `JNZ imm16` | 3 | |
| 1e | `JB imm16` | 3 | branch on CF |
| 1f | `CALL imm16` | 3 | `SP -= 2; [SP] = PC+3; PC = imm` |

Two details that matter and are easy to get wrong when re-implementing:

* `ROL8` (`0x401510`) reads the **byte** at `[rsp+rdx*2-0x18]` and writes back a
  zero-extended byte, so the register's high half is destroyed — it is a genuine 8-bit
  rotate, not a 16-bit one.
* `DIV` / `MOD` with a zero divisor do **not** fault. Both handlers branch to `0x401978`,
  which zeroes the destination register and continues. (A real `#DE` would have made a
  nice anti-emulation trap; the author guarded against it.)

## 4. Level 2 — the guest firmware is *another* VM

Disassembling the ROM from `0x0000` with the ISA above shows the "hypervisor's" guest is
itself an interpreter:

```
0000: MOVI R4, 0x2800      ; copy 0x100 bytes of initial data
0004: MOVI R5, 0x3800      ;   from ROM 0x2800  ->  RAM 0x3800
0008: MOVI R0, 0x0100
000c: LDB R3, R4 / STB R5, R3 / INC R4 / INC R5 / DEC R0 / CMPI R0,0 / JNZ 0x000c

001f: MOVI R1, 0x2000      ; R1 = L2 program counter (bytecode base 0x2000)
0023: MOVI R2, 0x3000      ; R2 = L2 stack pointer   (byte stack, ascending)
0027: MOVI R6, 0x3800      ; R6 = L2 data segment
002b: MOVI R7, 0x4000      ; R7 = user input

002f: LDB R3, R1 / INC R1  ; fetch L2 opcode
0034..00d2:                ; 23-way CMPI/JZ dispatch ladder
00d5: MOVI R0,2 / HLT R0   ; invalid L2 opcode -> return 2
```

Guest memory map:

```
0x0000  L1 program  (= the L2 interpreter)
0x2000  L2 bytecode
0x2800  L2 initial data image (in ROM)
0x3000  L2 operand stack
0x3800  L2 data segment (runtime copy of 0x2800)
0x4000  user input
```

### Recovered L2 instruction set (8-bit stack machine)

| Op | Mnemonic | Len | Semantics |
|----|----------|-----|-----------|
| 00 | `NOP` | 1 | |
| 01 | `PUSH imm8` | 2 | |
| 02 | `DROP` | 1 | |
| 03 | `DUP` | 1 | |
| 04 | `SWAP` | 1 | |
| 05 | `ADD` | 1 | `push (a + b) & 0xff` |
| 06 | `SUB` | 1 | `push (a - b) & 0xff` |
| 07 | `MUL` | 1 | `push (a * b) & 0xff` |
| 08 | `XOR` | 1 | |
| 09 | `AND` | 1 | |
| 0a | `OR`  | 1 | |
| 0b | `ROL` | 1 | `push rol8(a, b & 7)` |
| 0c | `MOD` | 1 | `push a % b` |
| 0d | `LDIN` | 1 | `push input[pop()]` |
| 0e | `LDD`  | 1 | `push data[pop()]` |
| 0f | `STD`  | 1 | `addr = pop(); val = pop(); data[addr] = val` |
| 10 | `EQ` | 1 | `push (a == b)` |
| 11 | `LT` | 1 | `push (a < b)`, unsigned, via L1 `CF` |
| 12 | `JMP imm16` | 3 | |
| 13 | `JZ imm16`  | 3 | pop; branch if `== 0` |
| 14 | `JNZ imm16` | 3 | pop; branch if `!= 0` |
| 15 | `ASSERTEQ` | 1 | pop `b`, pop `a`; if `a != b` then **`HLT 1`** |
| 16 | `HLT` | 1 | halt, returning `pop()` |

Operand order: in every binary op the **top of stack is the right operand** (`b`) and the
value beneath it is the left operand (`a`). This is visible in the handler shape
`DEC R2; LDB R4,[R2]` (that is `b`) followed by `DEC R2; LDB R5,[R2]` (that is `a`), then
e.g. `SUB R5,R4`. Getting this backwards silently breaks `SUB`, `MOD` and `ROL`.

## 5. The actual check

The L2 bytecode at `0x2000` is only **0x52 bytes** long:

```
0000: PUSH 0x2e / LDIN / PUSH 0x00 / ASSERTEQ   ; input[46] == 0  -> flag is 46 chars
0006: PUSH 0x00 / PUSH 0x00 / STD               ; data[0] = 0     (index i)
000b: PUSH 0x5a / PUSH 0x01 / STD               ; data[1] = 0x5a  (rolling key)

0010: PUSH 0x00 / LDD / PUSH 0x2e / EQ
0016: JNZ 0x004f                                ; i == 46 -> success

0019: PUSH 0x00 / LDD / LDIN                    ; c = input[i]
001d: PUSH 0x73 / MUL                           ; c * 0x73
0020: PUSH 0x45 / ADD                           ;   + 0x45
0023: PUSH 0x9b / XOR                           ;   ^ 0x9b
0026: PUSH 0x01 / LDD / XOR                     ;   ^ key
002a: PUSH 0x00 / LDD / PUSH 0x05 / MOD
0030: PUSH 0x01 / ADD / ROL                     ;   rol8 by (i % 5) + 1
0034: PUSH 0x3c / XOR                           ;   ^ 0x3c        -> t
0037: DUP / PUSH 0x01 / STD                     ; key = t        (ciphertext feedback!)
003b: PUSH 0x00 / LDD / PUSH 0x80 / ADD / LDD   ; expected = data[0x80 + i]
0042: ASSERTEQ                                  ; t == expected, else HLT 1

0043: PUSH 0x00 / LDD / PUSH 0x01 / ADD / PUSH 0x00 / STD   ; i++
004c: JMP 0x0010

004f: PUSH 0x00 / HLT                           ; return 0 -> Access Granted
```

Decompiled:

```c
uint8_t key = 0x5a;
for (int i = 0; i < 46; i++) {
    uint8_t t = input[i] * 0x73 + 0x45;
    t ^= 0x9b;
    t ^= key;
    t  = rol8(t, (i % 5) + 1);
    t ^= 0x3c;
    key = t;                       // CBC-like chaining on the ciphertext
    if (t != expected[i]) return 1;
}
return 0;
```

### The expected table

Lives in ROM at `0x2880`, i.e. ELF file offset `0x2120 + 0x2880 = 0x49a0`, copied to VM
address `0x3880` at boot. It is 46 bytes and ends exactly at ROM offset `0x28ad`, which
corroborates the length check:

```
3880: 29 0c f7 11 41 a7 d6 6c 80 82 eb 17 1a 32 b6 f6
3890: 37 ce 1d 6b 00 99 21 0b 17 c0 d4 a9 fd ae 23 58
38a0: 27 d8 72 44 a9 d0 a7 a0 16 89 14 40 90 f2
```

## 6. Inversion

Every step is invertible, and the chaining key at step `i` is simply `expected[i-1]` — the
*ciphertext* byte, which is already known. So this is a direct one-pass decrypt with no
search at all.

`0x73 = 115` is odd, hence invertible mod 256: `115⁻¹ mod 256 = 227 (0xe3)`.

```python
inv  = pow(0x73, -1, 256)                      # 0xe3
ror8 = lambda v, c: ((v >> (c & 7)) | (v << (8 - (c & 7)))) & 0xff if c & 7 else v

exp  = open('challenge', 'rb').read()[0x2120 + 0x2880:][:46]
key, flag = 0x5a, bytearray()
for i, t in enumerate(exp):
    x = ror8(t ^ 0x3c, (i % 5) + 1)            # undo ^0x3c and the rotate
    x ^= key                                   # undo ^key
    x ^= 0x9b                                  # undo ^0x9b
    x  = (x - 0x45) & 0xff                     # undo +0x45
    flag.append((x * inv) & 0xff)              # undo *0x73
    key = t                                    # chain on the ciphertext
print(bytes(flag))
```

```
b'bcsctf{vms_w1th1n_vms_4ll_th3_w4y_d0wn_a39f1c}'
```

## 7. Cross-validation

Two independent confirmations:

1. A faithful Python re-implementation of the **L1** interpreter (all 32 opcodes), run on
   the raw ROM with the candidate flag placed at `0x4000`, halts with return value **`0`**
   after ~10 300 L1 instructions.
2. The original ELF, run under WSL, prints `[+] Access Granted!` and exits `0`.

## 8. Notes and gotchas

* **`challenge_vm.bin` is a freebie, not a separate component.** It is byte-identical to
  the blob already embedded at `.rodata+0x120`. Handy for quick disassembly, but patching
  it changes nothing — `main` never opens the file.
* **Don't stop at one level.** The L1 dispatch loop *looks* like the whole VM, and it is
  where most of the 0x2900-byte ROM goes. The real check is one level further down and is
  only 82 bytes of L2 bytecode. This is why "find the comparison" static instincts fail
  here — there is no `memcmp`, no string, and the constants never appear in x86.
* **The keystream is ciphertext-chained.** A naive per-byte brute force against
  `expected[i]` with a fixed key succeeds at `i = 0` and then fails forever. Spotting
  `DUP / PUSH 1 / STD` at L2 `0x0037` is the crux of the challenge.
* **`input[46] == 0` is a length oracle** and it runs *before* any byte math, so a 46-byte
  answer is forced. It also tells you the table is 46 entries before you have read it.
* **Emulation beats symbolic execution here.** Writing the ~120-line L1 emulator takes less
  time than setting up angr, and it doubles as the verification harness.
* Zero-divisor handling (`DIV`/`MOD` -> 0) and the 8-bit-only `ROL8` are the two places a
  re-implementation is most likely to silently diverge; both are worth unit-testing against
  the real binary before trusting the emulator.

## Artifacts

* `vm.py` — L1 disassembler + emulator (all 32 opcodes)
* `l2dis.py` — L2 stack-machine disassembler + data-segment dump
* `solve.py` — inversion; prints the flag and re-runs the emulator to confirm a `0` return
