# dead_air — Writeup

**Category:** Reverse Engineering (RE + DSP)
**Files:** `dead_air` (ELF64 PIE, stripped, 22 760 B), `capture.wav` (12 kHz mono PCM16, 46.06 s)

## Flag

```
bupctf{th3_r34s0n_th1s_1s_h4rd_b3c4us3_1t_1s_l1k3_d34d_41r}
```

---

## TL;DR

`dead_air` is **not** an RTTY modem — the Baudot tables and the `NOT THE FLAG. BAUDOT HAS NO
BRACES.` string are bait. It is an **OFDM** modem (256‑pt IFFT, 64‑sample cyclic prefix, 40
subcarriers, adaptive bit‑loading). The visible payload carries the decoy traffic. The flag rides
a **covert side channel in the pilot tones**: each of the four pilots is rotated by
**±0.14 rad**, one reserved bit per pilot per OFDM symbol. Demodulate the pilot phase, reassemble
an `AC E1 | len | body | CRC‑16` record, and `inflate` the body.

---

## 1. Recon

```
$ file dead_air
ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a6be01a4..., stripped

$ file capture.wav
RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 12000 Hz
```

Imports are the giveaway: `sincos`, `sqrt`, `lround`, `fmod` next to `fopen`/`fwrite`. This thing
synthesises audio.

```
$ strings dead_air
...
ABCDEFGHIJKLMNOPQRSTUVWXYZ
1234567890-?:$!&#'()., ;/"
RIFF / WAVEfmt  / data
RYRY DE EP2AES QRV 7103 NR 1 NOT THE FLAG. BAUDOT HAS NO BRACES. VARAHF-RTTY-1S-A-D3C0Y-73 BTU OM KN
usage: %s <traffic.txt> <reserved.bin> <out.wav>
reserved.bin must be 1..255 bytes
reserved channel: %zu B body, %zu B record, %zu bits
burst %d: %zu B, %d payload symbols, %.2f s, %d reserved bits
wrote %s: %zu samples, %.2f s
```

Two things fall out immediately:

1. The two 26‑char strings are the ITA2 (Baudot) **LTRS** and **FIGS** rows, and the `RYRY DE …`
   string is a textbook RTTY over‑the‑air message. It even tells you it is a decoy
   (`D3C0Y`, `NOT THE FLAG`).
2. There is a second, undocumented **"reserved channel"** whose size is reported in *bits*. That
   is where the flag lives.

> **Tooling note (Windows host):** MinGW's `objdump` rejects the file
> (`File format not recognized`). Disassembly was done with **capstone** over the raw `.text`
> bytes (`0x1200`, length `0x2641`). Signal work used `numpy` + `scipy`.

---

## 2. `.rodata` triage

`.rodata` is at `0x4000`, `0x7e0` bytes. Dumping it gives almost the whole protocol spec:

| Address | Contents | Meaning |
|---|---|---|
| `0x4010` / `0x4023` | `ABC…Z`, `1234567890-?:$!&#'()., ;/"` | ITA2 LTRS / FIGS rows |
| `0x4060` | `RYRY DE EP2AES …` | decoy traffic |
| `0x41e0` | 256 × `uint16`, `[1]=0x1021`, `[2]=0x2042` | **CRC‑16/CCITT table** (poly `0x1021`) |
| `0x43e0` | 26 × `int`: 23,19,1,10,16,21,… | ITA2 codes for the FIGS row |
| `0x4460` | 26 × `int`: 3,25,14,9,1,13,26,20,… | ITA2 codes A–Z (`A=3, B=25, C=14, …`) |
| `0x4500` | `-3, -1, 1, 3` | 16‑QAM levels |
| `0x4580` | `1, 2, 3, 4` | bits per modulation mode |
| `0x4590` | `51, 38, 25, 12` | **pilot subcarriers** (in transmit order) |
| `0x45a0` | `12, 13, 14, … 51` (40 ints) | the 40 active subcarriers |
| `0x4678` | `3.1622776601683795` | `sqrt(10)` — 16‑QAM normalisation |
| `0x4680` | `17.5` | subcarrier‑index midpoint (`(36-1)/2`) |
| `0x4688`/`0x4690`/`0x4698`/`0x46a0` | `0.04`, `0.34`, `0.62`, `0.86` | bit‑loading jitter + thresholds |
| `0x46a0` | `12000.0` | sample rate |
| `0x46d8` | **`0.14`** | ← the covert‑channel phase step |

The ITA2 tables are complete and correct, which is exactly what makes the decoy convincing. They
are never used for the flag.

---

## 3. Static analysis of `main`

`e_entry = 0x33d0`; `_start` hands `main = 0x1240` to `__libc_start_main`. `main` is one huge
heavily‑inlined function. The interesting landmarks:

### 3.1 Subcarrier / pilot selection — `0x1264`

```asm
1264: lea  rax, [rip + 0x3335]        ; 0x45a0  -> subcarriers 12..51
1274: movabs rdi, 0xfff7ffbffdffefff  ; ~mask
1287: bt   rdi, rdx
128b: jb   0x129d                     ; bit set -> keep
```

`~0xfff7ffbffdffefff = 0x0008004002001000` → bits **12, 25, 38, 51**. Those four carriers are
pulled out as **pilots**; the remaining **36** carry data.

### 3.2 Constellations — `0x12d5` and `0x13a8`

```asm
1344: mov  eax, ebx
1355: sar  eax, 1
135e: xor  eax, ebx            ; Gray decode
136a: cvtsi2sd xmm0, eax
137e: call sincos              ; 8-PSK points, ebx = 1..7
```

```asm
13b4: lea  rdi, [rip + 0x3145] ; 0x4500 = {-3,-1,1,3}
13fe: divpd xmm0, xmm1         ; xmm1 = sqrt(10)
```

So the modem has BPSK / QPSK / 8‑PSK / 16‑QAM, all Gray mapped — matching the `{1,2,3,4}` table
at `0x4580`.

### 3.3 PN generator — `0x34c0`

An 11‑bit LFSR emitting `±1.0` doubles:

```asm
350a: shr  ecx, 0xa            ; out = state >> 10
350d: shr  edx, 8
3520: xor  edx, ecx            ; feedback = (s>>8) ^ (s>>10)
3527: subsd xmm1, xmm0         ; value = 1.0 - 2*out
352d: and  eax, 0x7ff
```

Called twice: 40 values with seed `683` (per‑subcarrier signs) and 65536 values with seed `0x5c3`
(the long pilot PN used at `0x207f`).

### 3.4 Reserved‑channel framing — `0x1483`–`0x1517`

```asm
1487: cmp  rax, 0xfe
148d: ja   0x3357              ; reserved.bin must be 1..255 bytes
1493: lea  r15, [rbx + 5]      ; record = len + 5
14a9: mov  word ptr [rax], 0xe1ac    ; magic AC E1 (little-endian store)
14b2: mov  byte ptr [rax + 2], bl    ; length
14bc: call memcpy                    ; body, verbatim
14d5: ...                            ; CRC-16/CCITT, init 0xFFFF, MSB-first
1513: mov  byte ptr [rdi + rbx + 3], ah   ; CRC hi
1517: mov  byte ptr [rdi + rbx + 4], al   ; CRC lo
```

**Record layout:**

```
+0      +1      +2      +3                 +3+len   +4+len
| AC  |  E1  |  len  |        body        |  CRC16 (big-endian)  |
```

Note the body is copied **verbatim** — no encryption in the binary. Whatever obfuscation exists is
inside `reserved.bin` itself.

### 3.5 Bursts, payload, scrambler

* `traffic.txt` is split on `"\n%%\n"` (`strstr` at `0x1588`), max **64** bursts (`0x1571`).
* LF is expanded to CRLF (`0x15cc`).
* Per burst: payload = text ‖ CRC‑16 (`0x190a`–`0x1953`), expanded to one byte per bit MSB‑first
  (`0x19bd`), padded to a whole number of OFDM symbols.
* Those bits are XORed with a **17‑bit LFSR** stream, seed `0x1d74`:

```asm
1a1f: mov  edx, 0x1d74
1a2e: shr  ecx, 0x10          ; out = state >> 16
1a31: shr  eax, 0xb
1a34: xor  eax, ecx           ; feedback = (s>>16) ^ (s>>11)
1a3e: and  eax, 0x1ffff
```

### 3.6 Adaptive bit loading — `0x17e0`–`0x186c`

For data‑carrier index `i = 0..35` in burst `b`:

```
q = |i - 17.5| / 17.5  +  (((3*b + 7*i) mod 5) - 2) * 0.04
mode = 3 if q < 0.34  else 2 if q < 0.62  else 1 if q < 0.86  else 0
bits_per_carrier = [1,2,3,4][mode]
```

i.e. carriers near the middle of the band get 16‑QAM, the edges get BPSK, with a deterministic
pseudo‑random wobble. The per‑carrier modes are transmitted in the header, 2 bits each.

### 3.7 Preamble / header — `0x1aa5`–`0x1c57`

Written as a bit array at `[rbp-0xcd0]`:

| Offset (bits) | Width | Field |
|---|---|---|
| 0 | 16 | sync word `0x5641` |
| 16 | 16 | payload length |
| 32 | 72 | 36 × 2‑bit modulation mode |
| 104 | 8 | burst index |
| 112 | 8 | burst count |

### 3.8 OFDM symbol synthesis — `0x3680`

```asm
368a: lea  r13, [rip + 0xfaf]  ; 0x4640 = end of subcarrier list
36ea: lea  r14, [rip + 0xeb3]  ; subcarrier list
3720: movsxd r15, dword [r14]  ; k
3755: call sincos              ; phase = 2*pi*k*n/256
3760: mulsd xmm0, [r15]        ; * Re(sym[k])
376b: mulsd xmm1, [r15 + 8]    ; * Im(sym[k])
...
37e6: lea  rbp, [rsp + 0x650]  ; emit samples 192..255 first  == 64-sample CP
3810: ...                      ; then all 256 samples
```

A hand‑rolled inverse DFT over the 40 active bins, emitting the **last 64 samples as a cyclic
prefix** followed by the full 256. So:

| Parameter | Value |
|---|---|
| Sample rate | 12 000 Hz |
| FFT size | 256 |
| Cyclic prefix | 64 |
| Symbol period | 320 samples = 26.67 ms |
| Carrier spacing | 46.875 Hz |
| Active carriers | 12…51 → 562.5 – 2390.6 Hz |
| Pilots | 12, 25, 38, 51 |
| Data carriers | 36 |

### 3.9 **The covert channel** — `0x20a9`–`0x214f`

This is the whole challenge:

```asm
209b: lea  r15, [rip + 0x24ee]   ; 0x4590 = {51,38,25,12}
207f: mov  rax, [rip + 0x447a]   ; the 65536-entry +-1 PN buffer
20b9: movsd xmm1, [rbx]          ; pn[i]  (the nominal pilot value)
20ae: mov  rdi, [rbp - 0xe00]    ; the reserved record
20cc: div  qword [rbp - 0xe20]   ; rdx = bit_index mod (8 * record_len)
20e0: shr  rax, 3
20eb: movzx eax, byte [rdi + rax]
20ef: and  ecx, 7                ; cl = 7 - (idx & 7)  -> MSB-first
20f9: sar  eax, cl
20fb: and  eax, 1                ; b
2100: sub  edx, eax              ; edx = 1 - 2*b
2106: mulsd xmm0, [rip + 0x25ca] ; * 0.14
210e: call sincos
213d: mulpd xmm0, xmm1           ; pilot = pn[i] * exp(j * theta)
2136: add  r14, [rbp - 0xe08]    ; bit_index += nsym
```

**Pilot = `pn[i] · exp(±j·0.14)`**, where the sign is `+` for a reserved bit of `0` and `−` for a
`1`. The bit index for pilot `k` of symbol `s` is `(s + k·nsym) mod (8·record_len)`, so
concatenating the four per‑carrier bit streams in the order `51, 38, 25, 12` reproduces the record
bitstream in order, repeated cyclically. Each burst restarts at bit 0 — the flag is sent six
times over.

An honest OFDM receiver only ever looks at `|pilot|` and `arg(pilot) mod π` for channel
estimation, so a 0.14 rad (8°) wobble is invisible. That's the "dead air".

---

## 4. Attacking `capture.wav`

### 4.1 Confirm the OFDM structure

Cyclic‑prefix autocorrelation (correlate `x[n]` with `x[n+256]` over a 64‑sample window) shows a
clean period‑320 peak, peak/mean ≈ 5.0. Symbol length 320 confirmed.

### 4.2 Burst segmentation

Band‑pass 500–2500 Hz, smooth the energy, threshold at 15 % of peak → **6 bursts**:

| # | samples | duration | symbols |
|---|---|---|---|
| 0 | 13 684 – 110 849 | 8.10 s | 303 |
| 1 | 119 801 – 209 971 | 7.51 s | 281 |
| 2 | 219 318 – 308 489 | 7.43 s | 278 |
| 3 | 315 245 – 347 084 | 2.65 s | 99 |
| 4 | 356 049 – 445 846 | 7.48 s | 280 |
| 5 | 454 283 – 546 639 | 7.70 s | 288 |

Between bursts the signal is just low‑level noise — literal dead air.

### 4.3 Symbol sync

Each burst starts at a different phase, so per burst sweep the offset `0…319` and keep the one
maximising Σ|mean(X²/|X|²)| over the four pilot bins (squaring removes the ±1 PN sign). Result:
`113, 113, 112, 83, 70, 93`.

### 4.4 Pilot phase extraction

Per burst and per pilot carrier:

1. `psi = ½·arg(mean(X²/|X|²))` — the static channel phase for that bin.
2. Derotate by `psi`, then fold into `(−π/2, π/2]` to strip the PN's ±1.
3. The residual lands at **±0.135 rad** — the 0.14 constant from `.rodata:0x46d8`. ✔

Positive residual → bit `0`, negative → bit `1`.

### 4.5 Frame alignment

Dropping the first **7** symbols of each burst (preamble/header) puts the magic exactly at bit 0 —
`1010 1100 1110 0001` = `AC E1` appears at bit offset 7 in every single burst, which is a nice
independent confirmation that the model is right.

Length byte = **67** → record = 72 bytes = **576 bits**.

### 4.6 Soft combine and verify

Sum the residual angles across all six bursts modulo 576 bits, then slice:

```
ace1 43 78f9c44309a74b2a2d482e49ab2ec9308e2f32362936c88b2fc9302c8e07a2
        0c93a294f824e36493d262e378c31290508e61b6717c8ab1494abc8961512d0
        080211493 df33

CRC-16/CCITT over the first 70 bytes = df33, stored = df33   -> OK
```

### 4.7 The body

The 67‑byte body starts `78 f9`. `0x78f9 % 31 == 0` with `CM=8, CINFO=7`, so it is a valid **zlib**
header — but `FDICT` is set, and bytes 2–5 give `DICTID = 0xc44309a7`, implying a preset
dictionary you do not have. That is the last piece of misdirection: the deflate stream never
actually back‑references the dictionary, so a raw inflate of `body[6:]` works:

```python
zlib.decompressobj(-15).decompress(body[6:])
b'bupctf{th3_r34s0n_th1s_1s_h4rd_b3c4us3_1t_1s_l1k3_d34d_41r}'
```

---

## 5. Solver

```python
#!/usr/bin/env python3
"""dead_air / capture.wav -- recover the pilot-phase covert channel."""
import sys, wave, zlib
import numpy as np
from scipy.signal import butter, filtfilt

FS, NFFT, CP = 12000, 256, 64
SYM      = NFFT + CP          # 320 samples
PILOTS   = [51, 38, 25, 12]   # .rodata:0x4590, in transmit order
PREAMBLE = 7                  # OFDM symbols before the reserved bitstream
MAGIC    = b"\xac\xe1"

def crc16_ccitt(data, crc=0xFFFF):
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def load(path):
    w = wave.open(path, "rb")
    return np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(float) / 32768.0

def find_bursts(x):
    b, a = butter(4, [500 / (FS / 2), 2500 / (FS / 2)], "band")
    e = np.convolve(filtfilt(b, a, x) ** 2, np.ones(SYM) / SYM, "same")
    d = np.diff((e > 0.15 * e.max()).astype(int))
    st, ed = np.where(d == 1)[0], np.where(d == -1)[0]
    return [(s, t) for s, t in zip(st, ed) if t - s > FS // 2]

def symbols(x, start, stop, off):
    idx = np.arange(start + off, stop - SYM, SYM)
    frames = x[np.add.outer(idx, np.arange(CP, CP + NFFT))]
    return np.fft.fft(frames, axis=1)[:, PILOTS]

def sync(x, start, stop):
    """Pick the symbol offset whose pilots are most phase-coherent."""
    best = (-1.0, 0)
    for off in range(SYM):
        P = symbols(x, start, stop, off)
        if len(P) < 10:
            continue
        sq = P ** 2 / (np.abs(P) ** 2 + 1e-12)
        score = np.abs(sq.mean(axis=0)).sum()
        if score > best[0]:
            best = (score, off)
    return best[1]

def soft_bits(P):
    """Residual pilot angle: +0.14 rad -> bit 0, -0.14 rad -> bit 1."""
    out = []
    for j in range(len(PILOTS)):
        v = P[:, j]
        sq = v ** 2 / np.abs(v) ** 2
        psi = np.angle(sq.mean()) / 2          # squaring kills the +-1 PN sign
        r = np.angle(v * np.exp(-1j * psi))
        r = np.where(np.abs(r) > np.pi / 2, r - np.sign(r) * np.pi, r)
        out.append(r[PREAMBLE:])
    return np.concatenate(out)                 # bits 0,1,2,... (mod record length)

def main(path="capture.wav"):
    x = load(path)
    streams = []
    for i, (s, t) in enumerate(find_bursts(x)):
        off = sync(x, s, t)
        P = symbols(x, s, t, off)
        print(f"burst {i}: samples {s}-{t}  offset {off}  {len(P)} symbols")
        streams.append(soft_bits(P))

    head = (streams[0] < 0).astype(np.uint8)
    assert np.packbits(head[:16]).tobytes() == MAGIC, "magic AC E1 not found"
    body_len = int(np.packbits(head[16:24])[0])
    nbits = (body_len + 5) * 8
    print(f"record: AC E1 | len {body_len} | body | crc16 -> {nbits} bits")

    acc = np.zeros(nbits)                      # soft-combine all bursts
    for s in streams:
        np.add.at(acc, np.arange(len(s)) % nbits, s)
    rec = np.packbits((acc < 0).astype(np.uint8)).tobytes()

    body = rec[3:3 + body_len]
    want = int.from_bytes(rec[3 + body_len:5 + body_len], "big")
    got = crc16_ccitt(rec[:3 + body_len])
    print(f"record hex : {rec.hex()}")
    print(f"crc16-ccitt: computed {got:04x} stored {want:04x} -> "
          f"{'OK' if got == want else 'MISMATCH'}")

    # zlib header has FDICT set, but the stream never uses the dictionary
    print("FLAG:", zlib.decompressobj(-15).decompress(body[6:]).decode())

if __name__ == "__main__":
    main(*sys.argv[1:])
```

Output:

```
burst 0: samples 13684-110849  offset 113  303 symbols
burst 1: samples 119801-209971 offset 113  281 symbols
burst 2: samples 219318-308489 offset 112  278 symbols
burst 3: samples 315245-347084 offset 83    99 symbols
burst 4: samples 356049-445846 offset 70   280 symbols
burst 5: samples 454283-546639 offset 93   288 symbols
record: AC E1 | len 67 | body | crc16 -> 576 bits
crc16-ccitt: computed df33 stored df33 -> OK
FLAG: bupctf{th3_r34s0n_th1s_1s_h4rd_b3c4us3_1t_1s_l1k3_d34d_41r}
```

---

## 6. The traps, collected

1. **Baudot / RTTY.** Complete, correct ITA2 tables plus a realistic ham message. Spending the
   evening writing an RTTY decoder gets you `VARAHF-RTTY-1S-A-D3C0Y-73`.
2. **The visible OFDM payload.** Fully decodable (header, adaptive bit loading, LFSR descrambler,
   CRC) — and it only ever yields the decoy traffic text.
3. **`reserved.bin` never appears in the binary's strings**, and the only hint it exists is the
   stderr line `reserved channel: … bits`, which you never see unless you run the encoder.
4. **The pilots look normal.** A real receiver checks `|pilot|` and phase modulo π; ±0.14 rad is
   well inside "channel estimation noise".
5. **The zlib preset‑dictionary bit** is set with a `DICTID` you cannot produce, to suggest a
   missing key. Raw inflate ignores it.

## 7. What actually gives it away

* The rodata constant `0.14` sitting alone among audio parameters, referenced exactly once, inside
  the pilot loop.
* `div` by `8 * record_len` immediately followed by a bit extraction `(byte >> (7 - (i & 7))) & 1`
  — nobody indexes a *modulation* table that way; that is a serialised byte buffer.
* The stderr message counting the reserved channel in **bits**, not bytes, when it is fed a
  byte‑aligned file. Bits only matter if you are dribbling them out a few per symbol.
