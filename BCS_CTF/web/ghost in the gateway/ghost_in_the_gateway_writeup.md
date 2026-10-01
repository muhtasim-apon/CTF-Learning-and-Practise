Solved on the first run.

  Flag

  bcsctf{h2_d0wngr4d3_d3sync_c4ch3_p01s0n1ng_succ3ss}

  How it worked

  The gateway is an h2c (HTTP/2 cleartext, prior-knowledge)
  front end that downgrades to HTTP/1.1 toward the Go backend
  over a pooled keep-alive socket. Its /internal filter only
  inspects the HTTP/2 :path pseudo-header — never the request
  body — so I smuggled the forbidden request inside the body:

  1. Stream 1 — an allowed GET /public/health with no
     content-length but a DATA-frame body of:
  GET /internal/flag HTTP/1.1\r\nHost: backend:15001\r\n\r\n
     The gateway forwards the health headers, then writes the
     body straight after. The backend reads the (bodyless)
     health request, then parses the leftover bytes as a second
     request — /internal/flag — and queues both responses on the
     keep-alive socket. The gateway reads only the first
     (health) response.
  2. Stream 3 — a plain GET /public/health on the same
     connection reuses the same poisoned upstream socket, so
     read_response hands back the queued /internal/flag response
     → the flag.

  The enabling bug was ProtocolAdapter.install() disabling h2's
  body-length validation combined with process_h2 forwarding
  request bodies (the HTTP/1.1 path doesn't) and reusing one
  upstream socket across all H2 streams — a classic
  HTTP/2→HTTP/1.1 downgrade desync / response-queue poisoning,
  exactly as the flag text confirms.
