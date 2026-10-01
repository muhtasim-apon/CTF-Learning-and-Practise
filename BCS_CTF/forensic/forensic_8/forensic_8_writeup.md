# Forensic Challenge 8 — BCSCTF Writeup

> **Category:** Forensics
> **Points:** 150
> **Solves:** 49
> **Difficulty:** Medium
> **Author:** jatisshor0081

---

## 1. Challenge Overview

> *"An automated alert flagged a leaked financial schema from a corporate accounting workstation. The primary target directory, containing upcoming projects sensitive information that were compromised. To prove corporate espionage, your assignment to extract information from the artifact and solve all forensic challenges from 1 to 10."*
>
> **Question 8:** *What is the full URL of the invoice document accessed by the user **arif** that routes to the **c2-gateway** host on **port 8080**?*

The artifact is a multi-segment **EWF (E01)** disk image (~14 GB logical, 6 segments) of a Windows workstation. We need to mount it, find user **arif**'s browser history, and extract the URL of a specific invoice accessed via the command-and-control gateway.

**Flag format:** `bcsctf{flag}`

---

## 2. Environment

| Tool | Purpose |
|------|---------|
| Python 3.13 | Scripting / forensic parsing |
| `pytsk3` (libtsk binding) | Filesystem walker (MFT / NTFS) |
| `dissect.evidence` | EWF/E01 image reader (chunk-decompressing stream) |
| Standard library `sqlite3` | Browser history database queries |
| OS: Windows 10 (Git Bash) | EWF segments co-located in working directory |

The image (bcsctf.E01 … E06) was provided via Google Drive / egovcloud, MD5
`caf70fd72dd354884095338a873cf026`, SHA1 `d60891020dc7028ef0d4c536b7c28cea227f761f`,
acquired with **FTK Imager 4.7.1.2** from a **VMware Virtual Disk** (lsilogic).

---

## 3. Methodology — High Level

1. **Open the E01 chain** with `dissect.evidence.EWF` (all 6 segments).
2. **Wrap it as a `pytsk3.Img_Info`** so we can use The Sleuth Kit's NTFS reader.
3. **Parse the MBR** to find the Windows NTFS partition's byte offset.
4. **Open NTFS** with `pytsk3.FS_Info` at that offset.
5. **Walk to arif's Chrome history DB**, read the SQLite file out through the image stream.
6. **Query `urls` table** for entries containing `c2-gateway` on `:8080` that point to an invoice document.
7. **Form the flag.**

---

## 4. Step-by-Step Walkthrough

### Step 1 — Loading the EWF chain

A naive `pytsk3.Img_Info('bcsctf.E01')` opens but rejects the disk as
*"Possible encryption detected (High entropy 8.00)"* — a false positive caused by
the compressed EWF payload confusing TSK's entropy heuristic.

`dissect.evidence`, by contrast, transparently decodes the EWF chunks, so we
wrap **its** stream into a tiny `pytsk3.Img_Info` subclass:

```python
import pytsk3
from dissect.evidence import EWF

class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf):
        self._ewf   = ewf
        self._size  = ewf.size
        self._stream = ewf.open()                            # AlignedStream over EWF
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_RAW)

    def get_size(self):
        return self._size

    def read(self, offset, size):                            # pytsk3 callback
        self._stream.seek(offset)
        return self._stream.read(size)

files = ['bcsctf.E01','bcsctf.E02','bcsctf.E03',
         'bcsctf.E04','bcsctf.E05','bcsctf.E06']            # ALL segments required
ev  = EWF(files)                                            # 15 032 385 536 bytes
img = EWFImgInfo(ev)
```

> Critical detail: `EWF` needs **every** segment as a list. Passing only `E01`
> causes `Missing EWF file for segment index: 1` as soon as pytsk3 reads past
> the first chunk.

### Step 2 — Parsing the MBR

Read the first 512 bytes (LBA 0) and look at the partition table:

```
Signature (offset 510–511):  55 AA   ✓ valid MBR

Part 0: type=0x07 NTFS   lba_start=2048     size=102400     (≈ 50 MB, Boot/EFI)
Part 1: type=0x07 NTFS   lba_start=104448   size=28334080   (≈ 14.5 GB, Windows)
Part 2: type=0x27        lba_start=28438528 size=921538     (≈ 450 MB, Recovery)
```

Byte offset of the Windows partition:

```
104448 sectors × 512 bytes/sector = 53 477 376  (0x03300000)
```

### Step 3 — Opening the NTFS filesystem

```python
fs = pytsk3.FS_Info(img, 53_477_376)
# FS type: NTFS (ftype=1), block size = 4096
```

The root listing contains everything you'd expect on a Windows install:

```
$AttrDef  $BadClus  $Bitmap  $Boot  $Extend  $MFT …
Documents and Settings  Downloads  PerfLogs  Program Files
ProgramData  Recovery  System Volume Information  Users  Windows
DumpStack.log.tmp  pagefile.sys  swapfile.sys  bootmgr
CompanyData  Desktop  ForensicGroundTruth  Lab …
```

### Step 4 — Locating user **arif**

```
/Users
├── All Users
├── arif            ← target
├── Default
├── Default User
├── desktop.ini
├── forensic
├── forensic.DESKTOP-N106FR1
├── Public
└── rahim
```

Listing `/Users/arif` confirms a normal user profile (`NTUSER.DAT`,
`AppData`, `Desktop`, `Downloads`, …).

### Step 5 — Finding the browser history database

Chrome's history lives at:

```
/Users/arif/AppData/Local/Google/Chrome/User Data/Default/History
```

(The file is `sqlite3`, ~160 KB, present in the `Default` profile folder
alongside `Login Data`, `Web Data`, `Cookies`, `Bookmarks`, etc.)

Reading the file through the image:

```python
f = fs.open('/Users/arif/AppData/Local/Google/Chrome/User Data/Default/History')
data = f.read_random(0, f.info.meta.size)        # 163 840 bytes
with open('chrome_history.db','wb') as out:
    out.write(data)
# Header: 53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33  → "SQLite format 3"
```

### Step 6 — Querying the URLs

```python
import sqlite3
conn = sqlite3.connect('chrome_history.db')
cur  = conn.cursor()

cur.execute("SELECT id, url, title, visit_count, typed_count, last_visit_time FROM urls")
rows = cur.fetchall()
# Total URLs: 6
```

| id | url |
|----|-----|
| 1 | `http://localhost:8080/login` |
| 2 | `http://secure-payroll.test:8080/` |
| 3 | `http://secure-payroll.test:8080/invoice/INV-2026-4451` |
| **4** | **`http://c2-gateway.test:8080/invoice/INV-2026-4451`** |
| 5 | `https://www.google.com/search?q=Invoke-WebRequest+%22http%3A%2F%2Fc2-gateway.test%3A8080%2Fbeacon%3Fhost%3Denv%3ACOMPUTERNAME…` |
| 6 | same Google search with extra tracking parameters |

Visit metadata for the c2-gateway hit:

```python
cur.execute("""
    SELECT urls.url,
           datetime(v.visit_time/1000000 + strftime('%s','1601-01-01'), 'unixepoch')
    FROM visits v JOIN urls ON v.url = urls.id
    WHERE urls.url LIKE '%c2-gateway%'
""")
# ('http://c2-gateway.test:8080/invoice/INV-2026-4451', '2026-09-19 16:04:17')
```

The URL contains everything the question asks for:

| Criterion from question | Found in URL |
|------------------------|--------------|
| Full URL               | ✅ `http://c2-gateway.test:8080/invoice/INV-2026-4451` |
| Invoice document       | ✅ path is `/invoice/INV-2026-4451` |
| Host `c2-gateway`      | ✅ `c2-gateway.test` |
| Port `8080`            | ✅ `:8080` |
| Accessed by user **arif** | ✅ Chrome profile is `/Users/arif/...` |

---

## 5. Flag

```
bcsctf{http://c2-gateway.test:8080/invoice/INV-2026-4451}
```

---

## 6. Key Forensics Lessons

1. **Always pass every segment** to an EWF/E01 loader — silent truncation leads
   to confusing errors far from the source.
2. **TSK can produce false-positives on EWF** (entropy heuristic). When that
   happens, layer a stream from a library that handles the format itself
   (`dissect.evidence`, `libewf`, `ewfmount`) and feed the bytes back into TSK.
3. **Browser history is a gold mine** for questions about visited URLs — every
   Chromium-based browser stores it in a plain SQLite DB at
   `<Profile>/Default/History` with a `urls` table (`url`, `title`,
   `visit_count`, `last_visit_time`) and a `visits` table (with timestamps in
   WebKit/Chrome epoch — microseconds since 1601-01-01).
4. **MBR partition table parsing** is just 16 bytes × 4 entries starting at
   offset 446; multiplying `lba_start` by 512 gives you the byte offset to
   hand to `pytsk3.FS_Info`.
5. The URL hit on **2026-09-19 16:04:17** lines up with the artifact acquisition
   date — a nice sanity check that we're reading the right user profile.

---

## 7. Appendix — Full Reproduction Script

```python
#!/usr/bin/env python3
"""Forensic Challenge 8 — BCSCTF — full reproduction."""
import sqlite3
import pytsk3
from dissect.evidence import EWF

# 1. Wrap EWF chain as pytsk3 image
class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf):
        self._ewf = ewf
        self._size = ewf.size
        self._stream = ewf.open()
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_RAW)
    def get_size(self): return self._size
    def read(self, off, n):
        self._stream.seek(off); return self._stream.read(n)

files = ['bcsctf.E01','bcsctf.E02','bcsctf.E03',
         'bcsctf.E04','bcsctf.E05','bcsctf.E06']
img = EWFImgInfo(EWF(files))

# 2. Parse MBR to find the Windows partition
mbr = img.read(0, 512)
assert mbr[510:512] == b'\x55\xaa'
for i in range(4):
    e = mbr[446 + i*16 : 446 + (i+1)*16]
    if e[4] != 0:
        print(f'Part {i}: type=0x{e[4]:02x} '
              f'lba_start={int.from_bytes(e[8:12],"little")} '
              f'size={int.from_bytes(e[12:16],"little")}')

# 3. Open the NTFS partition (Part 1: offset = 104448 * 512 = 53_477_376)
fs = pytsk3.FS_Info(img, 53_477_376)

# 4. Extract Chrome History DB
hist_path = '/Users/arif/AppData/Local/Google/Chrome/User Data/Default/History'
f = fs.open(hist_path)
db = f.read_random(0, f.info.meta.size)
with open('chrome_history.db','wb') as out: out.write(db)

# 5. Find the c2-gateway invoice URL
cur = sqlite3.connect('chrome_history.db').cursor()
cur.execute("SELECT url FROM urls WHERE url LIKE '%c2-gateway%:8080%invoice%'")
flag_url = cur.fetchone()[0]
print(f'\nFlag URL: {flag_url}')
print(f'Flag    : bcsctf{{{flag_url}}}')
```

**Output:**

```
Part 0: type=0x07 lba_start=2048 size=102400
Part 1: type=0x07 lba_start=104448 size=28334080
Part 2: type=0x27 lba_start=28438528 size=921538

Flag URL: http://c2-gateway.test:8080/invoice/INV-2026-4451
Flag    : bcsctf{http://c2-gateway.test:8080/invoice/INV-2026-4451}
```

---

*— Solved by extracting `INV-2026-4451` from arif's Chrome history at `/invoice/` on the attacker's `c2-gateway.test:8080`.*