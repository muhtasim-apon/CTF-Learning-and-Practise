# maze_runner — BCS CTF (Web)

> **Status:** unsolved during the live CTF window — only the reconnaissance / black-box analysis is preserved below.
> **Source files:** none available. The challenge server (`172.16.38.21:16000`, Apache/2.4.56 + PHP/8.0.30) was external; no PHP source, no game assets, and no flag were ever delivered back to disk. All artifacts in this folder come from the recon scripts in `../*.py` and the (mostly empty) captures in `../loot/`.

---

## 1. What we knew about the target

- **Hosts in scope:** `172.16.38.21` and `172.16.38.22` (reachable only via the BCS CTF VPN).
- **Port the maze runner ran on:** `16000/tcp`.
- **Banner / fingerprint** (`HEAD /`, captured in `../loot/stream_172-16-38-21_HEAD.txt`):
  ```
  HTTP/1.1 200 OK
  Date: Sat, 26 Sep 2026 08:23:05 GMT
  Server: Apache/2.4.56 (Debian)
  X-Powered-By: PHP/8.0.30
  Connection: close
  Content-Type: text/html; charset=UTF-8
  ```
  → an Apache-fronted PHP 8.0 application. The challenge name "maze_runner" and the recon wordlist (`/maze`, `/api/maze`, `/api/move`, `/api/start`, `/game`, `/play`, `/moves`, …) implied an interactive maze game with move/start/state endpoints.

The challenge brief mentioned the maze had to be "navigated" to reach a flag — strongly suggesting a stateful PHP backend (`/api/start` to begin, `/api/move` to step) that eventually returns `BCSCTF{...}` once the goal cell is reached.

---

## 2. The single observable behaviour: `GET /` **hangs**

Every PHP script that did a normal `GET /` against `:16000` hung indefinitely:

- `stream.py` — `GET /` for 12 s → 0 bytes (connection still open when timeout fires). Saved `../loot/stream_172-16-38-21_GET.txt` (0 bytes).
- `stream2.py` — same behaviour at 40 s with plain *and* browser headers. Both saves (`s2_GET__plain_wait40.txt`, `s2_GET__browser_wait40.txt`) are 0 bytes.
- `investigate.py` — confirmed the hang on a fresh connection (no bytes ever received before our timeout).
- `probe.py` — short 6 s timeouts all surfaced as `HANG/ERR` for `GET /`. Same for `POST /`, `PUT /`, `OPTIONS /`.
- `concurrent.py` — even firing a **second** concurrent `GET /` (the obvious "rendezvous / unblock" test) did not release the first connection. S1 (2×), S2 (3×) and S3 (`/` + `/solve.php` in parallel) all hung for the full 18 s read window with no first byte.

In contrast, `HEAD /` returned instantly with the headers above, and `OPTIONS /` likewise. So the body is what stalls — not the TCP listener.

### What that rules in / rules out

- **Not a TCP-level accept filter** — `HEAD` works.
- **Not a WebSocket-only app** — `recon.py`'s `Upgrade: websocket` test got no response either (`[no response - hung]`).
- **Likely a long-running PHP generator / `flush()` loop** — `text/html` `Content-Type` with no body until something happens, classic PHP "I'm holding the response open". Probably `ob_start` + periodic `flush()` waiting on user input.
- **Could be a per-request fork / child that waits for a partner** — ruled out by `concurrent.py`: a second connection does not wake the first.
- **Could be `max_execution_time`-driven** — `stream2.py` waited 42 s (well past the typical 30 s PHP limit) and still got 0 bytes. So either the script calls `set_time_limit(0)` *and* never echoes, or it's being held open outside PHP (e.g. `mod_php` waiting on a downstream `proxy:fcgi://`).

### Conclusion drawn at the time

The maze's `index.php` is a **state machine that emits the maze HTML only after a client interaction we never figured out**. Without a body, we never saw:
- the maze grid,
- the JS controller (which would have shown the actual `/api/move` request shape),
- or the success response with the flag.

That is why this challenge was not solved.

---

## 3. Recon pipeline that was attempted

All scripts live in `d:\CTF\BCS_CTF\web\` (one level up). The order they were run is below; everything is stdlib-only Python so it runs from WSL on the CTF VPN.

### 3.1 `recon.py` — Phase A black-box
Hits `172.16.38.21` and `172.16.38.22` on `:16000`:
- `GET /` (save body, dump, extract `<script src=…>` and inline JS)
- 30-path wordlist (`/maze`, `/api/maze`, `/api/move`, `/api/start`, `/api/state`, `/start`, `/move`, `/game`, `/play`, `/flag`, `/flag.txt`, `/source`, `/src`, `/app.js`, `/main.js`, `/maze.js`, `/static/`, `/assets/`, `/js/`, `/.git/HEAD`, `/.git/config`, `/admin`, `/debug`, `/status`, `/health`, …)
- **Output of the wordlist against `:16000`:** every request with status `< 400` would have been flagged `<== interesting` and saved. In the live run nothing came back before the 12 s `urllib` timeout — the homepage itself never returned, so no asset discovery ever ran.

### 3.2 `investigate.py` — raw-socket confirmation
- Port-scanned 38 candidate ports on `172.16.38.21`. Open ports during the run: `8888`, `8889`, `16000` (the maze runner) and a few others that turned out to belong to *other* web challenges on the same box (the "Reach Forums" Flask on `:8888`, the static mirror on `:8889`).
- Re-issued `GET /` over a raw socket with a 60 s read window — still no first byte. The hang is at the application layer, not the network.
- Issued an HTTP/1.1 WebSocket upgrade on `:16000` — also hung.

### 3.3 `stream.py` / `stream2.py` — long-poll / max-execution probes
- `stream.py` (12 s) and `stream2.py` (40 s, plain + browser headers) tried to catch either:
  - a slow PHP generator emitting the maze grid one cell at a time, or
  - PHP's 30 s fatal error after `max_execution_time`.
- Neither produced a single byte. All three saved captures are 0 bytes (see `../loot/`).

### 3.4 `concurrent.py` — rendezvous hypothesis
- F2 / F3 / F3+`/solve.php` concurrent connections tested whether a second TCP connection would unblock the first (e.g. two-player maze, or a write/read lock). All three scenarios stayed hung for the full read window.

### 3.5 `probe.py` — method & parameter fuzzing
- Tried `GET/HEAD/POST/OPTIONS/PUT /`.
- Tried 25 query params (`?debug=1`, `?source=1`, `?view=1`, `?page=1`, `?name=1`, `?level=1`, `?maze=1`, `?seed=1`, `?cmd=1`, `?input=1`, `?dir=1`, `?move=1`, `?moves=1`, `?path=1`, `?start=1`, `?x=1`, `?y=1`, `?token=1`, `?id=1`, `?action=1`, `?mode=1`, `?step=1`, `?help=1`, `?format=1`, `?output=1`) — all hung.
- Tried 8 POST bodies (`start=1`, `action=start`, `move=U`, `moves=UUUU`, `name=test`, `level=1`, JSON `{"start":true}`, empty).
- Probed `/assets/{index.html,index.php,app.js,main.js,style.css,maze.js,game.js,script.js,bundle.js,flag.txt,README.md,.htaccess}` — all hung or 404.
- Probed `/index.php?`, `/maze.php`, `/game.php`, `/api.php`, `/play.php`, `/solve.php`, `/info.php`, `/config.php`, `/server-status` — all hung or 404.

None of the parameter / body / method variants ever elicited a non-empty response from `:16000`.

### 3.6 Adjacent-box reconnaissance (`app_recon.py`, `discover.py`, `discover2.py`, `flag_probe.py`)
The same host was hosting several *other* web challenges on `:8888` (Flask "Reach Forums") and `:8889` (static mirror). Those scripts are unrelated to maze_runner, but they exist in the same folder. They did not interact with `:16000` and therefore did not advance the maze_runner solve.

---

## 4. What we never managed to do

The following steps would likely have cracked it, given more time / a teammate with browser access from the VPN:

1. **Open the page in a real browser** (Chrome / Firefox) via the BCS VPN. `HEAD` proves the server speaks HTTP; a browser would have rendered the maze once whatever JS event the PHP loop is waiting for fired. The hang is almost certainly a `WebSocket`/`EventStream` upgrade or an `XMLHttpRequest` long-poll that a browser completes and `urllib`/`socket` does not.
2. **Replay the browser's exact handshake** with the matching `Sec-Fetch-*`, `Accept`, `Cookie`, and either `Upgrade: websocket` *with a valid `Sec-WebSocket-Key`* or `Accept: text/event-stream` for SSE. The earlier WebSocket test used a freshly-random key but the server may have required a specific path or origin.
3. **Pull the static JS** (`/assets/maze.js`, `/static/game.js`, `/app.js`, …) once a working request shape is known — the controller function would have revealed `/api/move`'s exact contract (path, JSON body, auth header).
4. **Brute-force the maze with a `requests.Session()`**: once `/api/start` and `/api/move` are understood, write a BFS/DFS client that walks every reachable cell and dumps the response of the goal cell.

---

## 5. Files in this folder (delivered)

- `maze_runner_writeup.md` — this file.

The challenge's PHP source, the maze grid, and the flag were never obtained, so there is nothing else to commit. All the recon that *was* done lives one level up in `d:\CTF\BCS_CTF\web\` (`recon.py`, `investigate.py`, `stream.py`, `stream2.py`, `concurrent.py`, `probe.py`) and its loot in `d:\CTF\BCS_CTF\web\loot\` (`stream_172-16-38-21_HEAD.txt` is the only non-empty capture).

---

## 6. TL;DR

- Target = Apache/2.4.56 + PHP/8.0.30 at `172.16.38.21:16000`, challenge name "maze_runner".
- `HEAD /` → 200, `GET /` → **hangs forever** (verified up to 60 s, with plain and browser headers, with and without concurrent connections, on both candidate hosts).
- Every probe (method/param/body/path) hung identically; no JS, no maze, no flag ever came back.
- Best guess: the page uses a browser-driven transport (WebSocket or SSE) that `urllib`/`socket` clients never completed; opening it in a real browser on the VPN would have unblocked the solve.
- Not solved during the CTF.
