# Ransomware III — Writeup

**Category:** Forensics  
**Points:** 327  
**Author:** RayQuaZa

> i used an advanced cryptographic algorithm in my ransomware to make it unbreakable. Now im the victim of my own creation as i lost one of my important file during the ransomware execution. Recover the file data for me! i badly need it to continue developing my ransomware.

Flag format: `bupctf{[\x20-\x7e]+}`

## Flag

```
bupctf{g4rbl3d_c0d3_c4nn0t_h1d3_l1v3_k3y5}
```

---

## Files

- `file.bin`: 70 bytes of high-entropy data with no file magic.

```
00000000: 6e5a 1432 dfc5 4a1f b951 75e8 47a8 5606  nZ.2..J..Qu.G.V.
00000010: 48c6 e427 ee87 c5d1 f1bd 10b4 1b16 9db5  H..'............
00000020: 77c2 f420 f37c 6d18 cbdc 3bb4 7a1a e668  w.. .|m...;.z..h
00000030: 3414 67f3 0e85 b965 2e21 5e48 a9ec c5e0  4.g....e.!^H....
00000040: 7319 f9ef 0db3                           s.....
```

- `ransomware.raw`: the ~17.7 GB Windows 11 memory image from `ransomware.7z`. The same image is used in Ransomware II and V.

## 1. Finding the ransomware process

```
vol -f ransomware.raw windows.cmdline
```

| PID | Process | Command line | Verdict |
|---|---|---|---|
| 26324 | `MRCv120.exe` | `C:\Users\User\Downloads\MRCv120.exe` | Magnet RAM Capture, the tool that took the image. Not the malware. |
| 19976 | `claude.exe` | `"F:\claude.exe"` | **The ransomware.** It runs from a removable drive, uses a familiar name as cover, and started just before the capture. |

Dump the binary and the full process memory:

```
vol -f ransomware.raw -o evidence windows.pslist --pid 19976 --dump
vol -f ransomware.raw -o evidence windows.memmap --pid 19976 --dump   # -> pid.19976.dmp (~5 GB)
```

## 2. Triage of the binary

`claude.exe` is a PE32+ Go binary obfuscated with **garble**. The `main.*` symbols are renamed (`main.r90N0TO6_Nmg`, …), and string literals are encrypted and decoded at runtime by `main.decFunc`. `strings` therefore shows no ransom note, extension or key.

The linked crypto packages are still visible: `crypto/aes`, `crypto/cipher` (`cipher.NewGCM`, `cipher.NewCTR`), `crypto/rsa` and `crypto/ecdh`.

Reversing the garbled code isn't needed. **The process was still running when memory was captured**, so its AES key is still in the heap. As the flag puts it, garbled code can't hide live keys.

## 3. Finding the AES key in process memory (key-schedule scan)

Go's `crypto/aes` keeps the whole expanded key schedule in memory (on amd64, the AES-NI code writes it in standard byte order). Real key schedules can be told apart from random bytes with the first step of the AES key expansion:

```
w[Nk] = w[0] XOR SubWord(RotWord(w[Nk-1])) XOR Rcon[1]      (Nk = 4 for AES-128, 8 for AES-256)
```

This is the same idea `aeskeyfind` uses. The scan checks every 8-byte-aligned offset of `pid.19976.dmp` for AES-128 and AES-256 schedules. It is vectorised with numpy so the 5 GB dump takes about a minute. It found **11 candidate keys**.

## 4. Working out the file layout

AES-CTR, CBC and ECB with each candidate key produced only garbage. The earlier guess of a 16-byte IV plus 54 bytes of CTR data was wrong.

70 bytes also splits as **AES-GCM** in Go's usual `nonce || Seal()` layout:

```
[ 12-byte nonce ][ 42-byte ciphertext ][ 16-byte GCM tag ]
  6e5a1432dfc54a1fb95175e8
```

Go programs usually write `gcm.Seal(nonce, nonce, plaintext, nil)`, which puts the nonce in front of the ciphertext and tag.

Exactly one candidate key passes GCM tag verification:

```
key (AES-256) = 3d2c014b0f81ed1a1fc518754be9f2a42424744b41011d93f37972ebdfb817f2
```

A random key has a 2^-128 chance of passing the tag check, so this result proves that both the key and the layout are correct. The raw key also appears **12 times** in the `claude.exe` heap (for example at dump offsets `0x3e6208` and `0x428808`), where Go's `aes.Block` structs hold it. That confirms it belongs to the ransomware process.

## 5. Solver

```python
import mmap
import numpy as np
from Crypto.Cipher import AES

SBOX = np.frombuffer(bytes.fromhex(
 '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
 'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
 '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
 'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
 'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
 'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
 'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
 'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'), np.uint8)

def find_keys(path, chunk=1 << 26):
    keys = set()
    m = mmap.mmap(open(path, 'rb').fileno(), 0, access=mmap.ACCESS_READ)
    for base in range(0, len(m), chunk):
        b = np.frombuffer(m[base:base + chunk + 64], np.uint8)
        n = (len(b) - 48) // 8
        if n <= 0:
            break
        idx = np.arange(n) * 8
        for kl in (16, 32):                      # AES-128 / AES-256
            l = kl - 4                           # last word of the key
            t = (SBOX[b[idx+l+1]] ^ 1, SBOX[b[idx+l+2]], SBOX[b[idx+l+3]], SBOX[b[idx+l]])
            ok = np.ones(n, bool)
            for j in range(4):
                ok &= (b[idx+j] ^ t[j]) == b[idx+kl+j]
            for i in idx[ok]:
                k = bytes(b[i:i+kl])
                if len(set(k)) > 4:              # drop all-zero / low-entropy false positives
                    keys.add(k)
    return keys

ct = open('file.bin', 'rb').read()
nonce, body, tag = ct[:12], ct[12:-16], ct[-16:]
for k in find_keys('pid.19976.dmp'):
    try:
        print(k.hex(), AES.new(k, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(body, tag))
    except ValueError:
        pass
```

Output:

```
3d2c014b0f81ed1a1fc518754be9f2a42424744b41011d93f37972ebdfb817f2 b'bupctf{g4rbl3d_c0d3_c4nn0t_h1d3_l1v3_k3y5}'
```

## Takeaways

- If the ransomware process is still running when memory is captured, look for the key in its memory before reversing the binary. A key-schedule scan (aeskeyfind-style) works whatever obfuscation the binary uses.
- Obfuscators like garble hide symbols and string literals, but they cannot hide key material that is in use at runtime.
- To work out a file layout, try each common layout and let the authentication tag decide. Go's `gcm.Seal(nonce, nonce, pt, nil)` gives `nonce(12) || ct || tag(16)`. Here that is 70 = 12 + 42 + 16.
- "Advanced cryptographic algorithm" was AES-256-GCM. The algorithm is secure, but the key was left in RAM.
