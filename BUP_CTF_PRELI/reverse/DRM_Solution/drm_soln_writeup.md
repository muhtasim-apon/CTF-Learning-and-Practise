# Very Serious DRM Solution Writeup

## Challenge

The target was a DRM activation service:

```text
https://very-serious-drm-solution-93d67f8eea73.pwn.bupcopc.tech
```

The goal was to generate a valid workstation license and submit it to:

```text
POST /api/activate
```

The final solver is:

```text
reverse/DRM_Solution/ext/solve_drm.py
```

## Short Version

The diagnostic-token path was a decoy. The real solve uses the normal workstation activation path:

```text
product id: 0x20411
flags:      1
entitlement: 0x57
```

The server gives a live UID from:

```text
GET /api/instance
```

The UID controls several moving pieces:

- the expected 12-byte target block
- the native transform round keys
- the 96-bit bit permutation applied to the license payload

After reconstructing those pieces from `license_runtime.dll`, I modeled the transform in z3, inverted it, wrapped the solved 12-byte payload into the license envelope, and submitted the resulting key.

## License Format

Licenses are 25 Crockford-base32 characters, normally printed in five groups:

```text
XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
```

The decoded envelope is 125 bits:

```text
version      3 bits
payload     96 bits
entitlement 8 bits
crc16       16 bits
reserved    2 bits
```

The CRC is CRC16-CCITT-FALSE with initial value `0xffff`, over:

```text
uid_bytes || payload12 || entitlement || version
```

For workstation activation, the entitlement must be `0x57`.

## UID Handling

The UID looks like this:

```text
VS-AR8F-1HFQ-87DB-A9EP
```

Removing `VS-` and Crockford-decoding the remaining 16 characters gives 10 bytes:

```text
magic/version: 2 bytes
body:          6 bytes
crc16:         2 bytes
```

The first two bytes are expected to be:

```text
56 10
```

The final two bytes are a big-endian CRC16 over the first eight UID bytes.

## Native Runtime Flow

`VS_ProcessRequest` checks:

```text
request + 0x35: product id == 0x20411
request + 0x39: flags == 1 or flags == 4
```

The diagnostic path uses `flags == 4` and entitlement `0x44`, but `/api/activate` wants the workstation path:

```text
flags == 1
entitlement == 0x57
```

The workstation validation routine:

1. checks the license entitlement is `0x57`
2. derives a UID-specific seed
3. derives a UID-specific bit permutation
4. derives UID-specific round keys
5. transforms the 12-byte payload
6. compares it against the UID-specific target block

## UID-Derived Seed

The workstation seed is derived from:

```python
sha256(b"VS-DRM/WORKSTATION" + uid_ascii)
```

The first 16 digest bytes are interpreted as four little-endian 32-bit words:

```text
a, b, c, d
```

The runtime mixes them with rotates and constants:

```python
seed0 = rol32(a + 0x243f6a88, (c % 17) + 5) ^ b
seed1 = rol32(b - 0x7a5cf72d, (d % 17) + 5) ^ c
seed2 = rol32(c + 0x13198a2e, (a % 17) + 5) ^ d
seed3 = rol32(d + 0x03707344, (b % 17) + 5) ^ a
```

Those four words are packed little-endian into a 16-byte seed.

## Target Block

The expected transform output is not constant. It is derived from the live UID:

```python
target = sha256(b"activation" + uid_ascii + seed).digest()[:12]
```

For the final live instance used during solving:

```text
UID:    VS-AR8F-1HFQ-87DB-A9EP
seed:   f21ff7b4aac75eaa4ec1fd16dd260bc3
target: 9916ca4c33505f6702d26f9d
```

## Bit Permutation

Before the ARX transform, the 96-bit payload is permuted. This permutation is also UID-specific.

The runtime initializes a 96-byte identity table and shuffles it with a xorshift32 PRNG seeded from the workstation seed:

```python
state = rol32(seed_word2, 7) ^ seed_word0 ^ 0xa341316c
if state == 0:
    state = 0x6d2b79f5

perm = list(range(96))
for i in range(95, 0, -1):
    state ^= (state << 13) & 0xffffffff
    state ^= state >> 17
    state ^= (state << 5) & 0xffffffff
    state &= 0xffffffff
    j = state % (i + 1)
    perm[i], perm[j] = perm[j], perm[i]
```

The payload bits are read and written MSB-first.

## Round Keys

The transform uses 18 little-endian 16-bit round keys, also derived from the 16-byte seed.

The runtime builds six 32-bit mixed words from the seed words, then splits and folds them into 18 16-bit values. The solver implements this in `round_keys_from_seed()`.

For the final live UID:

```text
f00a2a33d7403d4f20705ccd50e978e2e198068217323af6cea720ae3fb49f14d2166bde
```

## Payload Transform

After bit permutation, the 12-byte state is split into two 6-byte halves:

```text
p = q[0:6]
s = q[6:12]
```

Each of six rounds builds three 16-bit words from `s`, applies add/rotate/xor operations, and emits a new 6-byte right half. The important detail is that this is Feistel-like:

```python
old_s = s
s = round_output ^ p
p = old_s
```

The final transformed block is:

```python
p + s
```

The first attempted model failed because it updated both halves with the round output. Matching the native leak DLL showed the correct state update was `p = old_s`.

## Inverting With z3

The transform is only 96 bits and uses bit-vector-friendly operations:

- 8-bit payload bytes
- 16-bit additions
- fixed rotates
- XORs
- byte extraction

So the solver declares 12 symbolic bytes for the permuted payload, runs the six native rounds symbolically, and constrains the result to equal the UID-derived target:

```python
solver.add(transformed_byte_i == target_byte_i)
```

Once z3 finds a model, the solver inverts the bit permutation to recover the actual 12-byte license payload.

## Local Validation

Before submitting remotely, the solver calls the local native runtime through `ctypes`:

```text
license_runtime.dll!VS_ProcessRequest
```

A valid workstation license returns:

```text
ret = 0
status = 0
entitlement = 0x57
```

Negative checks also behaved correctly:

- diagnostic entitlement `0x44` is rejected for workstation activation
- random `0x57` payloads are rejected

## Final Run

The final live run generated:

```text
UID:     VS-AR8F-1HFQ-87DB-A9EP
payload: 267722f98c50f29a0dbf1a4f
license: MK7E8-QSHH8-F56GD-QWD4Y-NSZ18
```

Native validation accepted it:

```text
native: ret=0 status=0 entitlement=0x57 receipt=0x1f9e54c629bbebae
```

Submitting it to `/api/activate` returned:

```text
{"ok": true, "flag": "bupctf{5e3M5_11K3_1_am_g377in6_la1d_oFF_500n_TWT}"}
```

## Flag

```text
bupctf{5e3M5_11K3_1_am_g377in6_la1d_oFF_500n_TWT}
```
