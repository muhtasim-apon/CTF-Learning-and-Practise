# reverse404 — Writeup

**Category:** Reverse Engineering
**Challenge prompt:** *"Why do I keep getting error 404?"*
**File:** `reverse404`

## Flag

```
bupctf{n3v3r_g0nn4_g1v3_y0u_up_n3v3r_g0nn4_l37_y0u_d0wn}
```

---

## 1. Recon

```
$ file reverse404
ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

Full RELRO, NX, stack canary, PIE, stripped — but tiny (`.text` is only 0x273 bytes), so there is
exactly one interesting function.

```
$ strings reverse404
...
Reverse 404
Access code:
404: Access not found.
Access restored.
```

No flag in the binary, so it is checked, not stored. `.rodata` is `0x98` bytes — bigger than those four
strings need, which hints at an embedded blob.

> Tooling note (Windows host): MinGW's `objdump` refuses the file (`File format not recognized`), and
> pwntools' `disasm()` fails for the same reason because it shells out to `objcopy`. Disassembly was done
> with **capstone** directly over bytes read through `pwnlib.elf.ELF`.

## 2. `main` @ `0x11e9`

The flow is straightforward:

```asm
1203  lea  rdi, [rip+0xdfa]        ; "Reverse 404"   -> puts
1220  lea  rdi, [rip+0xde9]        ; "Access code: " -> fwrite(stdout)
1238  mov  ebp, 0                  ; length = 0
123d  lea  rbx, [rsp-1]            ; buffer base (buf = rsp)
124b  call fgetc(stdin)
1257  cmp  eax, 0xa   / cmp eax,-1 ; stop on '\n' or EOF
1261  cmp  rbp, 0x39               ; hard cap 57 chars
```

Then the length gate:

```asm
128f  cmp  byte ptr [rsp+rbp-1], 0xd   ; strip a trailing '\r'
1294  cmovne rax, rbp
1298  cmp  rax, 0x38                   ; length must be exactly 56
129c  jne  0x1336                      ; -> "404: Access not found."
```

So the access code is **56 bytes** long.

## 3. The verification loop @ `0x12c5`

56 iterations (`esi` = `i`), OR-ing every mismatch into `r11d`; success only if `r11d == 0`.

```asm
12a2  lea  r10, [rip+0xdb7]   ; -> 0x2060, the 56-byte expected blob
12a9  mov  r9d, 0x31          ; k2
12af  mov  r8d, 0x5d          ; k1
12b5  mov  edi, 9             ; index accumulator
12ba  mov  r11d, 0            ; failure accumulator
12c0  mov  esi, 0             ; i

12c5  mov  eax, edi
12c7  shr  eax, 3
12cc  imul rax, rax, 0x24924925
12d3  shr  rax, 0x20
12d7  imul eax, eax, 0x38
12da  mov  edx, edi
12dc  sub  edx, eax           ; edx = edi % 56   <- buffer index

12de  mov  eax, r8d
12e1  xor  al, byte ptr [rsp+rdx]
12e4  add  eax, r9d           ; al = ((k1 ^ buf[idx]) + k2) & 0xff

12e7  mov  ecx, esi
12e9  imul rcx, rcx, 0x24924925
...
130c  add  ecx, 1             ; cl = (i % 7) + 1

130f  rol  al, cl
1311  xor  al, byte ptr [r10] ; compare against enc[i]
1317  or   r11d, eax          ; accumulate difference

131a  add  esi, 1
131d  add  edi, 0x11          ; +17
1320  add  r8d, 0x1d          ; +29
1324  add  r9d, 7             ; +7
1328  add  r10, 1
132c  cmp  esi, 0x38
132f  jne  0x12c5
```

### Decoding the obfuscation

Two things make this look worse than it is:

1. **Magic-constant division.** `0x24924925` is the reciprocal for dividing by 7. The first block does
   `(edi >> 3) / 7` then `* 56`, i.e. it computes `edi % 56`. The second block is the classic
   `x/7` sequence (`sub`, `shr 1`, `add`, `shr 2`), then `q*8 - q` to get `7q`, then `i - 7q` = `i % 7`.
2. **Strength reduction.** Every key is an arithmetic progression kept in a register instead of being
   recomputed, so no constant tables appear in the binary.

Rewritten per iteration `i`:

| value | expression |
|---|---|
| buffer index | `(9 + 17*i) mod 56` |
| xor key `k1` | `(0x5d + 0x1d*i) & 0xff` |
| add key `k2` | `(0x31 + 7*i) & 0xff` |
| rotate count | `(i mod 7) + 1` |
| expected | `enc[i]` at `.rodata:0x2060` |

**The check is:**

```
rol( ((k1 ^ buf[idx]) + k2) & 0xff , (i % 7) + 1 )  ==  enc[i]
```

Embedded blob at `0x2060` (56 bytes):

```
b81dd1609e8ce851726d48ecc49c7e60cfdb989ac14bb5ecefa9c4a5
c71385dd3350c31b118f009d86c0a50774590ed03d44bf883d42302d
```

## 4. Inversion

Since `gcd(17, 56) = 1`, the index map `(9 + 17*i) mod 56` is a **bijection** — each of the 56 input
bytes is touched exactly once. Every operation is invertible, so no bruteforce is needed:

```
t = ror(enc[i], (i % 7) + 1)
buf[(9 + 17*i) % 56] = ((t - k2) & 0xff) ^ k1
```

### `solve.py`

```python
from pwnlib.elf import ELF

enc = ELF('reverse404', checksec=False).read(0x2060, 56)

ror = lambda v, c: ((v >> (c % 8)) | (v << (8 - c % 8))) & 0xff

buf = [0] * 56
for i in range(56):
    idx = (9 + 17 * i) % 56
    k1  = (0x5d + 0x1d * i) & 0xff
    k2  = (0x31 + 7 * i) & 0xff
    t   = ror(enc[i], (i % 7) + 1)
    buf[idx] = ((t - k2) & 0xff) ^ k1

print(bytes(buf).decode())
```

Output:

```
bupctf{n3v3r_g0nn4_g1v3_y0u_up_n3v3r_g0nn4_l37_y0u_d0wn}
```

## 5. Verification

The binary is a Linux ELF and could not be executed on the analysis host, so the result was checked by
re-encrypting the recovered string with the forward transform and comparing to `.rodata`:

```python
rol = lambda v, c: ((v << (c % 8)) | (v >> (8 - c % 8))) & 0xff
f = b'bupctf{n3v3r_g0nn4_g1v3_y0u_up_n3v3r_g0nn4_l37_y0u_d0wn}'
out = bytes(
    rol(((((0x5d + 0x1d * i) & 0xff) ^ f[(9 + 17 * i) % 56]) + ((0x31 + 7 * i) & 0xff)) & 0xff,
        (i % 7) + 1)
    for i in range(56)
)
assert out == enc          # True
assert len(f) == 56        # passes the 0x38 length gate
```

Both hold, so feeding this string to `Access code:` prints `Access restored.` instead of
`404: Access not found.`

## 6. Takeaways

- `0x24924925` (and friends like `0xAAAAAAAB`, `0x66666667`) are compiler magic reciprocals — recognise
  them as division, not crypto.
- Arithmetic progressions in registers are compiler strength reduction of `k1 + step*i`; unroll them
  mentally into closed form and the "obfuscation" disappears.
- A stride that is coprime with the buffer length is a permutation, which means the check is a clean
  1-to-1 mapping and inverts directly.
- When native binutils can't read the target format, capstone over raw section bytes is enough.
