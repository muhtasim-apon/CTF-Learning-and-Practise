# Ransomware IV — Writeup (UNSOLVED)

**Category:** Forensics
**Points:** 451
**Author:** RayQuaZa

> For recoveribility, after primary encryption, it generates a 32-byte hexadecimal string which is
> supplied to the secondary encryption. Find it for me which may help me to recover my files.

Flag format: `bupctf{[\x20-\x7e]+}`

> **Status: NOT SOLVED.** `bupctf{3d2c014b0f81ed1a1fc518754be9f2a42424744b41011d93f37972ebdfb817f2}`
> (the DEK in hex) was submitted and **rejected**. This document records the scheme, the evidence,
> and what has been ruled out, so the next attempt does not repeat the same work.

---

## The malware

`F:\claude.exe` (PID 19976), a Go binary obfuscated with **garble**: `main.*` symbols renamed,
string literals decrypted at runtime. All findings below come from the process memory
(`ransomware1/evidence/pid.19976.dmp`), where the decrypted strings and live key material sit.

## 1. The scheme (established)

Decrypted strings in the Go heap describe the whole workflow:

| Heap offset | Content |
|---|---|
| `0x300260` | `Target directory to encrypt` (a CLI flag description) |
| `0x300280` | `[*] Encryption engine on : %s` |
| code `0x61b2dd` | `movabs rsi, 0x626a6e622e` = `.bnjb`, the extension for encrypted files |
| `0x310000` | `-----BEGIN PUBLIC KEY-----` … an **RSA-3072** public key, e = 65537 |
| `0x31bc4e` | `encrypted_dek.bin` |
| `0x31bb70` | `session_metadata.json` |
| `0x2fa920` | `"EncryptedDEK"`, `"HardwareProfile"`, `"TargetPath"`, `"Timestamps"`, `"Version"` |

So it is the usual hybrid scheme:

```
             primary                                secondary
file  ──AES-256-GCM(DEK)──>  file.bnjb        DEK ──RSA-3072-OAEP(pub)──>  EncryptedDEK
```

Five finished session records are in memory (four in the heap, one more in the raw image). Each
`EncryptedDEK` base64-decodes to exactly **384 bytes** = one RSA-3072 ciphertext. Note these records
were **read from disk** by the malware (it was encrypting recycled `session_metadata.json` copies in
`F:\$RECYCLE.BIN\`), so most belong to *earlier* runs:

```
ts 1788187165  (2026-08-31 14:39 UTC)  MAC …:04
ts 1790535058  (2026-09-27 18:50 UTC)  MAC …:05
ts 1790537798  (2026-09-27 19:36 UTC)  MAC …:05
ts 1790538243  (2026-09-27 19:44 UTC)  MAC …:05   <- the captured run
```

`HardwareProfile` is the victim fingerprint the description calls "for verifications":

```
Rakin + 178BFBFF00A20F12 + 79B80982-05F8-5B19-AD68-047C16E2CB7A + E2034233DG562P + 0a:00:27:00:00:05
hostname   CPU ID           baseboard UUID                         disk serial      MAC
```

The console screen buffer still in the image prints each component (UTF-16LE, e.g. physical offset
`0x165738340`): `[*] Hostname: Rakin`, `[*] MAC Address: …`, `[*] CPU ID: 178BFBFF00A20F12`,
`[*] Physical Cores: 8`, `[*] Baseboard UUID: …`, `[*] Disk Serial Number: E2034233DG562P`,
`[*] Is SSD: false`. **No hex string is printed.**

## 2. The crypto span in the heap

One 32-byte size-class span holds everything the crypto touched:

| Offset | Value | Identified |
|---|---|---|
| `0x320300` | `3d2c014b0f81ed1a1fc518754be9f2a42424744b41011d93f37972ebdfb817f2` | **the AES-256 DEK** (11 more copies in `aes.Block` structs at `0x3e6208`…) |
| `0x320360` | `3040746b8e65bf2159d012a01342c175d1825508d2cf5279dcadf32f2b9c1eec` | `SHA-256(HardwareProfile)` |
| `0x3204c0` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `SHA-256("")` = OAEP's `lHash` (empty label) → the secondary layer is **RSA-OAEP/SHA-256** |
| `0x3204e0` | `ac925242e5dde8095bb57a7f5a2536f73beea7a2af6ce63609aff9a62a9daf08` | **unidentified** |
| `0x320500` | `07118f948edd2454bc59a2df6a0b2925b054d2ff54a8f16757dca30aa188a8d5` | **unidentified** |

The DEK is genuine: it decrypts Ransomware III's `file.bin` (`nonce(12) ‖ ct(42) ‖ tag(16)`) and the
GCM tag verifies, yielding `bupctf{g4rbl3d_c0d3_c4nn0t_h1d3_l1v3_k3y5}`.

Working hypothesis for the two unknowns: they are the leftover MGF1 digest scratch buffers from the
two `mgf1XOR` calls inside Go's OAEP (`digest = hash.Sum(digest[:0])` allocates 32 bytes on the
first iteration of each call). That would make them
`SHA-256(seed ‖ 0000000a)` and `SHA-256(maskedDB ‖ 00000000)` — neither invertible.

## 3. What has been ruled out

- **`hex(DEK)` is not the flag.** Submitted and rejected. Consistent with the fact that the string
  `3d2c014b0f81ed1a…` does **not** occur anywhere in the 17.7 GB image (`rg -a -i '3d2c014b0f81ed1a'`
  → 0 hits), i.e. the malware never materialised the DEK as hex.
- **There is exactly one AES key in the process.** A byte-granular key-schedule scan (AES-128/192/256)
  over the malware's entire Go heap returns only the DEK. So there is no second symmetric layer with
  its own key, and no AES key that is itself an ASCII hex string.
- **No hex string exists in the heap.** A full-dump scan for delimited 32- and 64-character
  lowercase hex runs returns 8339 unique strings, **none** of them below offset `0x1000000`
  (the Go heap). An unaligned scan of `0x2e0000–0x800000` for any `[0-9a-fA-F]{24,80}` run returns a
  single hit, `B8EB6A3D6E35B442A59B52A0BF2D5CBB` — the `/ID` of the PDF the malware was reading
  (`Windows10Enterprise22H2HashValues.pdf`), not something it generated.
- **The RSA plaintext is not recoverable.** The public key only (3072-bit) is present. A full-dump
  search for the OAEP-encoded block `em = 0x00 ‖ maskedSeed ‖ maskedDB` (unmask, then require
  `db[:32] == lHash`) tested 13,642,804 aligned candidates and found none, so `em` no longer exists
  in memory.
- **Hash-derivation guesses fail.** Neither unknown value is `SHA-256`/`SHA-512`/`SHA-1`/`MD5`/
  `BLAKE2s`/`SHA3-256` of, nor `HMAC` over, any pairing of: the DEK, `hex(DEK)`, the HardwareProfile
  (both MAC variants), its SHA-256, the public key DER/PEM/modulus, the metadata JSON, `file.bin`
  and its nonce/ct/tag/plaintext, or the carved PDF.
- **The encrypted output is not in the heap.** Using the known DEK and the PDF plaintext carved at
  `0x39d000`, a scan for a buffer `N(12) ‖ C` with `C[:16] == pt[:16] XOR AES_K(N‖00000002)` found
  nothing, so no `.bnjb` ciphertext buffer was retained.
- **No data files are dumpable from the process.** `windows.dumpfiles --pid 19976` yields only DLLs
  plus `claude.exe` itself; the malware had closed its file handles. The on-disk `claude.exe`
  (10,932,224 bytes) has `Go buildinf` with module path `unknown` (garble stripped it).
- **The encrypted files are not in the image at all.** `windows.filescan` over the full image
  (32,321 file objects) contains **no** `.bnjb`, `encrypted_dek.bin` or `session_metadata.json` file
  object — only `\claude.exe` (and a `\claude\claude.exe`). The `F:` volume's contents were not in the
  cache. *Note:* `filescan` dies early with `UnicodeEncodeError` on Windows unless
  `PYTHONIOENCODING=utf-8 PYTHONUTF8=1` is set — that is why an earlier attempt produced 667 lines.
- **No ciphertext produced by this DEK exists anywhere in the image.** Known-plaintext carve over all
  17.7 GB: for every 4 KiB page plus byte offsets 0–63, check whether
  `AES-ECB-dec(ct[0:16] XOR pt[0:16])` ends in `00000002` (the GCM counter-2 block — this needs no
  knowledge of the nonce and no assumption about a header). Plaintexts tried: the carved PDF
  (`%PDF-1.7…`), the PNG magic, `desktop.ini`, `%PDF-1.6`, and `{"EncryptedDEK":` for the recycled
  JSON copies. **Zero hits.** The recycled `$R*.bnjb` files belong to earlier runs with other DEKs,
  and the captured run (started 19:44:00, imaged seconds later) had not written one yet.
- **`EncryptedDEK` is genuinely RSA, not AES.** All three 384-byte blobs were tried as AES-GCM under
  every candidate key (DEK, fingerprint hash, both unknowns, and the hex-string candidates as ASCII)
  in three nonce/tag layouts; no tag verifies.
- **The DEK is not derived from the two unknown buffers** either: no SHA-256/SHA-512/SHA3/BLAKE2s of
  them (raw or hex, upper or lower), no HMAC in either direction, no HKDF with salt `∅`/profile/
  fingerprint, and no XOR, produces the DEK.
- **No hex string sits anywhere near the ransomware's metadata.** Taking all 565 offsets in the image
  where `EncryptedDEK`, `HardwareProfile`, `session_metadata`, `encrypted_dek` or `.bnjb` appears, and
  scanning ±8 KiB around each for delimited 32/64-char hex runs, yields 28 unique strings — every one
  unrelated (Stripe SVG asset hashes, WinSxS manifest GUIDs, Copilot debug nonces, browser-cache
  filenames, a CloudFront `Via` id). None is key material.

## 4. Where to go next

1. ~~Find a `.bnjb` file's actual bytes and read its header.~~ **Done — not possible.** The 118
   `.bnjb` and 119 `encrypted_dek.bin` references in the image are all *filename* strings (MFT/index
   records and the malware's own heap), not file content; `filescan` proves no such file object is
   cached, and the known-plaintext carve proves no ciphertext under this DEK is present either.
2. **Untested candidates**, in order of plausibility. Every one is a value the malware demonstrably
   computed or held, rendered as hex:
   | # | value | why |
   |---|---|---|
   | 1 | `3040746b8e65bf2159d012a01342c175d1825508d2cf5279dcadf32f2b9c1eec` | `SHA-256(HardwareProfile)`, cached at heap `0x320360` beside the DEK — the "verification" value that travels with the wrapped key |
   | 2 | `ac925242e5dde8095bb57a7f5a2536f73beea7a2af6ce63609aff9a62a9daf08` | unidentified 32-byte buffer at `0x3204e0`, inside the OAEP working set |
   | 3 | `07118f948edd2454bc59a2df6a0b2925b054d2ff54a8f16757dca30aa188a8d5` | unidentified 32-byte buffer at `0x320500` |
   | 4 | `79B8098205F85B19AD68047C16E2CB7A` | baseboard UUID with dashes stripped — literally a 32-character hex string (try lowercase too) |
   | 5 | `3D2C014B0F81ED1A1FC518754BE9F2A42424744B41011D93F37972EBDFB817F2` | the DEK, uppercase |
   | 6 | `96e5aad961e1e6f5b557974feba1674a` | `MD5(DEK)` — a 32-character hex "key ID" |
   | 7 | `469a2ffaaaff542493eed6e7373985c0284f57600802dafca06ccc1eb3789d02` | `SHA-256(DEK)` — a key checksum for verification |
   | 8 | `B8EB6A3D6E35B442A59B52A0BF2D5CBB` | the only 32-char hex string that exists in the heap (the encrypted PDF's `/ID`) |
3. **Reverse the garbled wrap routine.** `main.main` is at RVA `0x62aee0` (reached via
   `runtime.mainPC` at `0x9e6908` → `0x62aee0`, found from the PE entry `0x79620` →
   `runtime.rt0_go` `0x76460`). The crypto/rsa function carrying `crypto/rsa: message too long for
   RSA key size` is at `0x644b00`. Calls go through func-pointer tables (e.g. `encoding/hex.Encode`
   at `0x45dfc0`, whose pointer lives at `0x9edf00`), so the call graph built from direct `E8` calls
   does not reach them — an emulator or a Go-aware decompiler is needed.

## Files

`solve.py` recovers and verifies the DEK (it prints the value that was rejected — keep it for the
key-schedule scan, which is reusable, not for its flag line).

---

# FLAGS TO SUBMIT — try in this order

Every candidate is a value the malware demonstrably computed or held, rendered as a hexadecimal
string. Submit top to bottom and stop at the first accept.

```
bupctf{3040746b8e65bf2159d012a01342c175d1825508d2cf5279dcadf32f2b9c1eec}
bupctf{ac925242e5dde8095bb57a7f5a2536f73beea7a2af6ce63609aff9a62a9daf08}
bupctf{07118f948edd2454bc59a2df6a0b2925b054d2ff54a8f16757dca30aa188a8d5}
bupctf{79B8098205F85B19AD68047C16E2CB7A}
bupctf{79b8098205f85b19ad68047c16e2cb7a}
bupctf{96e5aad961e1e6f5b557974feba1674a}
bupctf{469a2ffaaaff542493eed6e7373985c0284f57600802dafca06ccc1eb3789d02}
bupctf{3D2C014B0F81ED1A1FC518754BE9F2A42424744B41011D93F37972EBDFB817F2}
bupctf{B8EB6A3D6E35B442A59B52A0BF2D5CBB}
bupctf{b8eb6a3d6e35b442a59b52a0bf2d5cbb}
```

What each one is, and why it is on the list:

| # | flag body | what it is | why it fits "a 32-byte hexadecimal string supplied to the secondary encryption" |
|---|---|---|---|
| 1 | `3040746b…1eec` | `SHA-256(HardwareProfile)`, cached in the heap at `0x320360` | sits directly beside the DEK and the OAEP scratch; it is the "for verifications" fingerprint that travels with the wrapped key |
| 2 | `ac925242…af08` | unidentified 32-byte heap buffer at `0x3204e0` | allocated inside the RSA-OAEP working set, immediately after `lHash` |
| 3 | `07118f94…a8d5` | unidentified 32-byte heap buffer at `0x320500` | the next allocation in that same set |
| 4/5 | `79B80982…CB7A` | baseboard UUID with the dashes stripped (upper, then lower) | literally a 32-**character** hexadecimal string, and it is one of the collected identity values |
| 6 | `96e5aad9…674a` | `MD5(DEK)` | a 32-character hex "key ID" — the usual shape of a recovery/verification token |
| 7 | `469a2ffa…9d02` | `SHA-256(DEK)` | a key checksum, i.e. "for verifications … proper recover support" |
| 8 | `3D2C014B…17F2` | the DEK, uppercase | the lowercase form was rejected; Go's `hex.EncodeToString` is lowercase, but `%X` is not |
| 9/10 | `B8EB6A3D…5CBB` | the encrypted PDF's `/ID` | the **only** 32-character hex string that actually exists in the malware's heap |

If every one of these is rejected, stop guessing: the remaining route is to Unicorn-emulate the wrap
path in `claude.exe` (see §4 above) and observe the exact buffer handed to the RSA call.
