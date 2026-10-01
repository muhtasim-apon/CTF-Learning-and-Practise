 Wiretrap — BCS CTF (Network, Medium) Writeup

  Flag: bcsctf{1cmp_c0v3rt_ch4nn3l_dh_k3y_xch4ng3_7a3f2b}

  Challenge

  ▎ We intercepted network traffic from a compromised machine. 
  ▎ Analysts say it's just routine ICMP monitoring. Something
  ▎ was exfiltrated. Can you find out what?

  File: capture (1).pcap, 28,980 bytes, 254 packets.

  ---

  1. Triage

  Every packet is ICMP echo, and every payload is 56 bytes.
  Grouping the packets by conversation shows two kinds of
  traffic:

  ┌──────────────────┬─────────┬────────────────────────────┐
  │     Traffic      │ Packets │     What it looks like     │
  ├──────────────────┼─────────┼────────────────────────────┤
  │ Random 10.x /    │         │ Only echo-requests, random │
  │ 172.16.x /       │ 200     │  ICMP id/seq, random       │
  │ 192.168.x hosts  │         │ payloads. This is noise.   │
  ├──────────────────┼─────────┼────────────────────────────┤
  │ 10.13.37.1 ↔     │         │ Fixed ICMP id 0xa0f0, seq  │
  │ 10.13.37.2       │ 54      │ 0–26 in order, request and │
  │                  │         │  reply pairs.              │
  └──────────────────┴─────────┴────────────────────────────┘

  Three things are wrong with the 10.13.37.x conversation:
  - Each echo-reply payload is different from its request. A
    real ping reply echoes the request payload back.
  - Every request starts with the magic bytes DE AD.
  - In the seq=1 exchange, the request comes from .2, so traffic
    flows both ways.

  This is the covert channel.

  2. Reversing the protocol

  Here are the first few bytes of some frames:

  dead 01 0000 0018 abcd 000001000000000f 0000000000000005
  000000fb185e132d
  dead 02 0001 0008 2eab 0000008a33d0088b
  dead 03 0002 0018 77d6 4f355be4549fd562...
  dead 05 001a 0000 ffff

  The frame layout (the rest of the 56 bytes is random padding):

  +-------+------+----------+----------+-----------+-----------+
  | DE AD | type | seq u16BE| len u16BE| chk u16BE | data[len] |
  +-------+------+----------+----------+-----------+-----------+

  - The type-05 FIN frame has empty data and a checksum of FFFF.
    FFFF is exactly what CRC-16/CCITT-FALSE (poly 0x1021, init
    0xFFFF) returns for empty input. Running that CRC over the
    data of every frame matches the chk field, which confirms
    the layout.
  - Message types:

  ┌──────┬───────────┬───────────────────────────────────────┐
  │ Type │ Direction │                Meaning                │
  ├──────┼───────────┼───────────────────────────────────────┤
  │ 01   │ .1 → .2   │ HELLO: the Diffie-Hellman parameters  │
  ├──────┼───────────┼───────────────────────────────────────┤
  │ 02   │ .2 → .1   │ Server's DH public key                │
  ├──────┼───────────┼───────────────────────────────────────┤
  │ 03   │ .1 → .2   │ Data stream A (seq 2–13, sent in      │
  │      │           │ order)                                │
  ├──────┼───────────┼───────────────────────────────────────┤
  │ 04   │ .1 → .2   │ Data stream B (seq 14–25, sent out of │
  │      │           │  order)                               │
  ├──────┼───────────┼───────────────────────────────────────┤
  │ 05   │ .1 → .2   │ FIN                                   │
  └──────┴───────────┴───────────────────────────────────────┘

  3. The handshake is Diffie-Hellman

  HELLO data, read as three big-endian u64 values:

  p = 0x000001000000000F = 2^40 + 15   (prime)
  g = 0x0000000000000005 = 5
  A = 0x000000FB185E132D

  Server reply: B = 0x0000008A33D0088B

  4. Breaking the DH exchange

  A 40-bit prime is far too small, and p − 1 factors smoothly:

  p − 1 = 2 · 3 · 5 · 36650387593

  Pohlig–Hellman solves each discrete log instantly
  (sympy.discrete_log):

  a = 457190135943
  b = 319549626691
  s = B^a mod p = A^b mod p = 0xB94B3B5C6C   ✔ (both sides
  agree)

  5. Key derivation and decryption

  The CRC covers the ciphertext, so it can't be used to check a
  guessed key. Instead, I reassembled stream 03 in seq order,
  tried common key derivations, and looked for known file
  headers. This one works:

  key = SHA256( s.to_bytes(8, 'big') )
      = 50be53e4c62c7208ef5fe67059e50eb8c9042e08102320a553ef138b
  ae8ee284
  plaintext = ciphertext XOR key (the 32-byte key repeated)

  The decrypted stream starts with 1f 8b 08 00, the gzip header.
  Decompressing it gives:

  CLASSIFIED - TOP SECRET
  ========================
  Operation: WIRETAP
  Date: 2026-09-14
  Status: EXFILTRATION COMPLETE

  Target network credentials recovered.
  Primary access code:
  bcsctf{1cmp_c0v3rt_ch4nn3l_dh_k3y_xch4ng3_7a3f2b}

  Secondary assets staged for retrieval.
  All tracks covered — ICMP tunnel active.

  --- END OF TRANSMISSION ---

  6. Stream 04 is a decoy

  Stream 04 is 248 bytes, sent out of order and reordered by
  seq. It doesn't decrypt under any variant I tried:
  - key derived with MD5, SHA1, SHA256, SHA512, SHA3 or BLAKE2
  - secret encoded big- or little-endian, as 5, 8, 16 or 32
    bytes
  - stream offsets, per-chunk key reset, and domain-separated
    keys

  Its entropy is about 7.08 bits/byte, which is what random
  bytes of that length look like. The only "hits" were
  raw-deflate false positives, because raw deflate accepts
  almost any input. It is filler meant to waste time, matching
  the note's "secondary assets" wording.

  ---

  Solver

  from scapy.all import rdpcap, ICMP
  import sympy, hashlib, zlib

  pk = rdpcap('capture (1).pcap')
  frames = {}
  for p in pk:
      d = bytes(p[ICMP].payload)
      if d[:2] == b'\xde\xad':
          t, seq = d[2], int.from_bytes(d[3:5], 'big')
          ln = int.from_bytes(d[5:7], 'big')
          frames[seq] = (t, d[9:9+ln])

  hello = frames[0][1]
  P = int.from_bytes(hello[0:8], 'big')
  g = int.from_bytes(hello[8:16], 'big')
  A = int.from_bytes(hello[16:24], 'big')
  B = int.from_bytes(frames[1][1], 'big')

  a = sympy.discrete_log(P, A, g)          # Pohlig-Hellman, p-1
  is smooth
  s = pow(B, a, P)
  key = hashlib.sha256(s.to_bytes(8, 'big')).digest()

  ct = b''.join(x for q, (t, x) in sorted(frames.items()) if t
  == 3)
  pt = bytes(c ^ key[i % 32] for i, c in enumerate(ct))
  print(zlib.decompress(pt, 31).decode())  # gzip

  Takeaways

  - Echo-replies that don't echo the request and a fixed ICMP id
    with increasing seq are the giveaways for a tunnel hidden
    in ping noise.
  - A per-frame CRC gave away the frame layout: the empty FIN
    frame's FFFF was the known CRC-16 value that confirmed it.
  - DH over a 40-bit prime with smooth p − 1 gives no security,
    since Pohlig–Hellman recovers the private keys immediately.
  - Flag: bcsctf{1cmp_c0v3rt_ch4nn3l_dh_k3y_xch4ng3_7a3f2b}
