# Forensic Challenge 9 — Deleted file under Project-Orion

**Category:** Forensics · **Points:** 150 · **Author:** jatisshor0081

## Question
> What is the original filename of the deleted file that initially existed under the
> directory `C:\Users\rahim\Documents\Project-Orion`?

**Flag format:** `bcsctf{flag}`

## Answer
```
bcsctf{budget_review.csv}
```
(fallback transcription: `bcsctf{budget_review}`)

The deleted file's original filename is **`budget_review.csv`**.

---

## Artifacts
EnCase image set `bcsctf.E01`–`bcsctf.E06`, extracted to
`D:\CTF\BCS_CTF\forensic\forensicchall_1\extracted`.

Volume layout used for all reads:
- Partition 1 (NTFS): byte offset `104448 * 512`, size `28334080 * 512`.

All analysis was **read-only** (dissect.evidence / dissect.ntfs, pure Python — no EWF
mount required).

## Investigation

### 1. Locate Project-Orion and enumerate current contents
Walking `Users\rahim\Documents\Project-Orion` resolves to **MFT segment 74657**.
Its `$I30` directory index and the raw `$MFT` FILE_NAME records list only three
*surviving* files:

| File | MFT record |
|------|-----------|
| `contatcss.txt` | 99402 |
| `New Rich Text Document.rtf` | 99401 |
| `Notes.txt` | 99397 |

No deleted (not-in-use) MFT record still carried a FILE_NAME whose parent reference
was 74657 — so the deleted entry had already been unlinked from the directory index
and its record either reused or overwritten.

### 2. USN Journal — dead end
Parsing `\$Extend\$UsnJrnl:$J` (~53 MB, 39k records) produced **zero** events whose
parent segment was 74657, and no `Project-Orion` create/rename event at all. The
journal had wrapped past the Orion activity, so it could not name the deleted file.

### 3. Recycle Bin `$I` metadata — the authoritative source
The file was not permanently deleted; it was sent to the Recycle Bin. Each deleted
item stores a `$I######.<ext>` metadata file whose header records the **original full
path**, size and deletion time.

Parsing every `$I` file under `\$Recycle.Bin`, rahim's SID
`S-1-5-21-1883243207-2011820343-4193110713-1005` contained:

```
$IKTDV01.csv : size=1353  orig = C:\Users\rahim\Documents\Project-Orion\budget_review.csv
$INDDRUU.rtf : size=7     orig = C:\CompanyData\Finance\New Rich Text Document.rtf
```

Only `$IKTDV01.csv` maps back to the target directory `Project-Orion`. Its original
name is **`budget_review.csv`** (1353 bytes). The `.rtf` entry originated from
`C:\CompanyData\Finance`, so it is not the answer.

`$I` (v2) header layout used to decode:
```
0x00  u64  version (== 2)
0x08  u64  original file size
0x10  u64  deletion time (FILETIME)
0x18  u32  path char count (incl. NUL)
0x1C  ...  original path (UTF-16LE)
```

## Chain of evidence
`\$Recycle.Bin` → rahim SID `...-1005` → `$IKTDV01.csv` header →
`C:\Users\rahim\Documents\Project-Orion\budget_review.csv`.

## Reproduce
`scratchpad/recycle.py` opens the E01 set read-only, walks `\$Recycle.Bin`, and prints
the decoded original path of every `$I` metadata file.

## Flag
```
bcsctf{budget_review.csv}
```
