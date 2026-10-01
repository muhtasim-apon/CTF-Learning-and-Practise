# palimpsest — Writeup

**Category:** Crypto
**Prompt:** *"The conservator swears every page uses a fresh press. Under ultraviolet light, each symbol
has three depths, yet the same erased text keeps showing through."*
**Files:** `palimpsest.py`
**Service:** `ncat --ssl palimpsest-<id>.pwn.bupcopc.tech 1337`

## Flag

```
bupctf{cUbiC_Re51du3s_UNv31l_er4s3D_7Rit5}
```

---

## TL;DR

The scheme is **Naccache–Stern**. The prime generator forces `p ≡ 1 (mod 6)`, so a cubic residue
character `χ(x) = x^((p-1)/3)` always exists. `χ` is a group homomorphism onto `μ₃ ≅ Z/3`, and the
ciphertext is a product of public roots raised to the plaintext trits:

```
c = Π rootsᵢ^dᵢ   ⇒   log χ(c) = Σ dᵢ · log χ(rootsᵢ)  (mod 3)
```

Since `dᵢ ∈ {0,1,2}` there is **no reduction loss** — that is one exact linear equation per sample,
in the digits themselves. Each `SAMPLE` is a fresh key over the *same* plaintext, so 40+ samples give
a full-rank 40×40 system over GF(3). Solve it, reassemble the blocks, done. No discrete log, no
knapsack, no meet-in-the-middle.

That is the palimpsest: every fresh page leaks one more trace of the same erased text.

---

## 1. The scheme

`palimpsest.py` is a clean Naccache–Stern implementation.

**Parameters** (`NTRITS = 40`, `PRIME_BITS = 512`, `BLOCK_RADIX = 3^40`):

```python
PRIMES = SMALL_PRIMES[:NTRITS]        # the first 40 primes: 2,3,5,...,173
assert prod(prime**2 for prime in PRIMES) < 1 << (PRIME_BITS - 1)
```

**Key generation:**

```python
def generate_params():
    p = random_cubic_prime()
    while True:
        s = secrets.randbelow(p - 3) + 2
        if gcd(s, p - 1) == 1:
            break
    inverse = pow(s, -1, p - 1)
    roots = tuple(pow(prime, inverse, p) for prime in PRIMES)
```

So `rootsᵢ = primeᵢ^(1/s) mod p`. Public: `(p, roots)`. Private: `s`.

**Encryption** — the message is written in base 3, one trit per small prime:

```python
for root in params.roots:
    block, digit = divmod(block, 3)
    ciphertext = ciphertext * pow(root, digit, params.p) % params.p
```

i.e. `c = Π rootsᵢ^dᵢ mod p` with `dᵢ ∈ {0,1,2}` the trits of the block.

**Decryption** raises `c` to the secret `s`, which collapses the roots back to the small primes:

```
c^s = (Π primeᵢ^(1/s · dᵢ))^s = Π primeᵢ^dᵢ  =: M
```

`M < Π primeᵢ² < 2^511 < p`, so no wraparound occurs and `M` can simply be trial-divided by the 40
small primes to read the trits back off. The assertion on line 128 is exactly what guarantees this.

## 2. Reconnaissance of the service

```
$ ncat --ssl palimpsest-<id>.pwn.bupcopc.tech 1337
PALIMPSEST/1
Commands: SAMPLE, INFO, QUIT
READY
INFO
{"version":1,"trits":40,"samples_remaining":56}
```

`SAMPLE` returns one JSON object and then **closes the connection** — one sample per TCP session,
56 sessions total per instance:

```json
{"p": 9151368806...771,
 "roots": [7581590094..., ...40 entries...],
 "ciphertexts": [5035451964..., ...6 entries...]}
```

Six ciphertext blocks × 40 trits ≈ 6 × 63.4 bits ≈ 380 bits ≈ 47 bytes of plaintext — a flag.

The important observation, and the one the prompt hands you: **`p`, `s` and therefore `roots` are
fresh on every sample, but the six ciphertext blocks always encrypt the same plaintext.** "Every page
uses a fresh press, yet the same erased text keeps showing through."

## 3. The bug

Look at how primes are generated:

```python
def random_cubic_prime(bits=PRIME_BITS):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1))
        candidate -= candidate % 6
        candidate += 1                      # candidate ≡ 1 (mod 6)
        while candidate.bit_length() == bits:
            if is_probable_prime(candidate):
                return candidate
            candidate += 6                  # stays ≡ 1 (mod 6)
```

Every prime satisfies `p ≡ 1 (mod 6)`, hence **`3 | p − 1`, always**. That is not incidental — the
function is literally named `random_cubic_prime`, and "each symbol has three depths" is the hint.

When `3 | p − 1`, the cubic residue character

```
χ(x) = x^((p−1)/3) mod p
```

is a surjective group homomorphism `F_p^* → μ₃ = {1, ω, ω²}`. Fix a generator `ω` of `μ₃` (take any
`g` with `g^((p−1)/3) ≠ 1`) and define `L(x) ∈ {0,1,2}` by `χ(x) = ω^{L(x)}`. Then `L` is a
homomorphism onto `Z/3`:

```
L(xy) = L(x) + L(y)  (mod 3)
```

Apply it to the ciphertext. Because `c = Π rootsᵢ^dᵢ mod p`:

```
L(c) = Σ_{i=0}^{39} dᵢ · L(rootsᵢ)   (mod 3)
```

Everything except the `dᵢ` is **public**: `L(rootsᵢ)` and `L(c)` are computed with one modular
exponentiation each. And critically the trits satisfy `dᵢ ∈ {0,1,2}`, so `dᵢ mod 3 = dᵢ` — the
equation constrains the digits *exactly*, with no information lost to reduction.

So each sample yields:

* one coefficient row `a = (L(roots₀), …, L(roots₃₉)) ∈ (Z/3)^40`, essentially uniformly random,
* one right-hand side `bₖ = L(cₖ)` **per block** `k`.

Since the six blocks share the same coefficient row, this is a single matrix with six RHS columns.
Collect `N ≥ 40` samples, get a full-rank system, and recover all 240 trits at once.

### Why it breaks so completely

Naccache–Stern's security rests on the knapsack `c = Π rootsᵢ^dᵢ` being hard to invert — the naive
search is `3^40 ≈ 1.2·10^19`, meet-in-the-middle still `3^20 ≈ 3.5·10^9`. The character attack sidesteps
the group entirely: it projects onto the order-3 quotient where the "knapsack" is just linear
algebra. One sample alone leaks only ~1.58 bits and is useless; the fatal design choice is
**re-encrypting the same plaintext under many independent keys**, which turns 1.58 bits per sample
into a solvable linear system.

If `p ≡ 1 (mod ℓ)` for other small `ℓ`, the same trick applies with the `ℓ`-th power residue
character — but `ℓ = 3` is *guaranteed* here, and 3 is exactly the radix, which makes the leak
perfectly aligned with the digits.

## 4. Exploit

### 4.1 Harvest

One sample per connection, so open connections in parallel and collect ~49 of the 56 available:

```python
import socket, ssl, json, threading, queue

H = "palimpsest-<id>.pwn.bupcopc.tech"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
out = queue.Queue()

def one():
    try:
        c = ctx.wrap_socket(socket.create_connection((H, 1337), timeout=30), server_hostname=H)
        c.settimeout(60)
        f = c.makefile("rwb")
        for _ in range(3):
            f.readline()                      # banner
        f.write(b"SAMPLE\n"); f.flush()
        for _ in range(4):
            line = f.readline()
            if not line:
                break
            t = line.decode().rstrip()
            if t.startswith("{"):
                out.put(json.loads(t))
                break
        c.close()
    except Exception:
        pass

threads = []
for i in range(48):
    t = threading.Thread(target=one); t.start(); threads.append(t)
    if len(threads) % 6 == 0:                 # gentle on the server
        for t in threads: t.join()
        threads = []
for t in threads: t.join()

samples = list(out.queue)
json.dump(samples, open("samples.json", "w"))
```

### 4.2 Solve

```python
import json

NTRITS = 40
BLOCK_RADIX = 3 ** NTRITS

def char_log(x, p, e, w):
    """L(x) with chi(x) = x^((p-1)/3) = w^L(x)."""
    v = pow(x, e, p)
    return 0 if v == 1 else (1 if v == w else 2)

samples = json.load(open("samples.json"))
nblocks = len(samples[0]["ciphertexts"])

rows, rhs = [], []
for s in samples:
    p = s["p"]
    e = (p - 1) // 3
    g, w = 2, None
    while w is None:                          # any non-cubic-residue fixes a generator of mu_3
        t = pow(g, e, p)
        if t != 1:
            w = t
        g += 1
    rows.append([char_log(r, p, e, w) for r in s["roots"]])
    rhs.append([char_log(c, p, e, w) for c in s["ciphertexts"]])

# Gauss-Jordan over GF(3), all six RHS columns at once
M = [rows[i] + rhs[i] for i in range(len(rows))]
pivots, r = [], 0
for col in range(NTRITS):
    sel = next((i for i in range(r, len(M)) if M[i][col] % 3), None)
    if sel is None:
        continue
    M[r], M[sel] = M[sel], M[r]
    inv = pow(M[r][col], -1, 3)
    M[r] = [(v * inv) % 3 for v in M[r]]
    for i in range(len(M)):
        if i != r and M[i][col] % 3:
            f = M[i][col]
            M[i] = [(a - f * b) % 3 for a, b in zip(M[i], M[r])]
    pivots.append(col); r += 1

assert r == NTRITS, f"rank {r} < 40, collect more samples"
for i in range(r, len(M)):                    # surplus rows must be consistent
    assert not any(M[i]), "inconsistent system"

digits = [[0] * NTRITS for _ in range(nblocks)]
for i, col in enumerate(pivots):
    for k in range(nblocks):
        digits[k][col] = M[i][NTRITS + k]

blocks = [sum(d * 3 ** i for i, d in enumerate(dg)) for dg in digits]
value = 0
for b in reversed(blocks):                    # encode_blocks emits least-significant first
    value = value * BLOCK_RADIX + b
print(value.to_bytes((value.bit_length() + 7) // 8, "big"))
```

Output:

```
rank 40
b'bupctf{cUbiC_Re51du3s_UNv31l_er4s3D_7Rit5}'
```

With 49 samples the system had rank 40 and the 9 surplus equations were all consistent — a free
self-check that the recovered trits are correct, independent of the flag being readable ASCII.

## 5. Notes

* **Block order.** `encode_blocks` uses `divmod(value, BLOCK_RADIX)` and appends, so `blocks[0]` is
  the *least* significant. Reassemble in reverse.
* **Digit order.** `encrypt_block` peels `divmod(block, 3)` in the order of `PRIMES`, so `rootsᵢ`
  carries the coefficient of `3^i`.
* **Only 56 samples.** The budget is deliberately just above the 40 needed. With bad luck a batch can
  come out rank-deficient over GF(3); 45–50 samples gives comfortable margin (a random 49×40 matrix
  over GF(3) is full rank with probability > 99.9%).
* **Sample count is per instance, not per connection** — `samples_remaining` keeps decreasing across
  reconnects, so don't burn them probing.

## 6. Fix

Any one of these kills the attack:

1. Don't force `p ≡ 1 (mod 6)`. Use `p ≡ 2 (mod 3)`, where the cube map is a bijection and no cubic
   character exists. (Other small factors of `p − 1` would still need care.)
2. Don't re-encrypt the same plaintext under fresh keys — a single sample leaks only ~1.58 bits and
   is harmless.
3. Randomise the encryption. Textbook Naccache–Stern is deterministic and unpadded; adding a random
   multiplier from a known-order subgroup, or padding the message, destroys the fixed linear relation
   the attack solves for.
