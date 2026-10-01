# Ransomware V — Writeup

**Category:** Forensics  
**Points:** 379  
**Author:** RayQuaZa

> I wrote something confidential, but forgot where and what it was exactly. But surely I know it starts with bup. Find it for me, please!

Flag format: `bupctf{[\x20-\x7e]+}`

## Flag

```
bupctf{Str1ng5_f41led_y0u_buT_i_g0T_yoU}
```

---

## Files

This challenge uses the same `ransomware.raw` as the other Ransomware challenges. It is a ~17.7 GB Windows 11 memory image, extracted from `ransomware.7z`.

## 1. First attempt: search for the flag directly

The description says the secret "starts with bup", so the obvious move is to search the image for the flag format in ASCII and in UTF-16LE:

```bash
rg -a -o 'bupctf\{[\x20-\x7e]{1,80}\}' ransomware.raw | sort | uniq -c
```

```
      3 bupctf{draft_flag}
      2 bupctf{ctf}
      1 bupctf{draft_fl}
```

The UTF-16LE search turned up only these:

- `bupctf{this_base_has_enough_lowercase_letters_for_leet_encoding}`, which is text from an AI-chat / writeup context
- about 14 hits of an Obsidian CRC homework note that ends like this:

```
Now, lets divide $...$ by $...$ to get the reminder $R(X)$,
$$
\begin{align}
\end{align}
$$

bupctf{
```

The note has `bupctf{` and then nothing, and every copy of it in memory looks the same. None of these results is the real flag. The challenge title hints at why: the flag is not stored as one contiguous string.

## 2. Spotting the split flag

Near one of the `bupctf{` hits, at physical offset `0x3c4c1b0cd`, there is a page that looks compressed. It contains readable pieces of a different note:

```
1. AES or RSA ?.2..his faster but symmetric .3..).is slow...a..,4. Maybe use
..bu...pct..f{Str1...ng5_...fail..}
```

The flag pieces `bu`, `pct`, `f{Str1`, `ng5_`, `fail` and `}` sit on **separate lines with tab indentation**. A regex for `bupctf\{...\}` can never match that.

### Decompressing the page (Snappy)

The gaps between the readable pieces are Snappy tags. Snappy is the compression LevelDB uses, so this page belongs to Chromium/Electron IndexedDB, which Obsidian uses. For example:

| bytes | meaning |
|---|---|
| `01 c6` | copy-1: copy 4 bytes from 198 bytes back |
| `14` | literal: 6 bytes follow (`$ by $`) |
| `1c` | literal: 8 bytes follow (`$ to get`) |

A small Snappy decoder that starts at a known tag boundary recovers the older version of the note:

```
1. AES or RSA ?
2. AES is faster but symmetric
3. RSA is slow but asymmetric
4. Maybe use...

bu
		pct
	f{Str1
		ng5_
		fail
	}
```

That version gives `bupctf{Str1ng5_fail}`. Another UTF-16 page contains leetspeak pieces (`f41l`, `y0u`, `_yoU`, …), which shows that the note was **edited afterwards**. We need the newest version.

## 3. Searching for the surrounding text instead of the flag

Searching for the text *around* the flag is more reliable than searching for the flag itself. I searched the whole image, in chunks to keep RAM use low, for `RSA is slow`, `Maybe use`, `f41l` and `_yoU`, in both ASCII and UTF-16LE:

```python
keys = [b'Maybe use', b'RSA is slow', b'f41l', b'_yoU']
keys += [k.decode().encode('utf-16le') for k in keys]
f = open('ransomware.raw', 'rb'); CH = 1 << 24; pos = 0; prev = b''
while (b := f.read(CH)):
    buf = prev + b
    for k in keys:
        o = buf.find(k)
        while o >= 0:
            print(hex(pos - len(prev) + o), k)
            o = buf.find(k, o + 1)
    prev, pos = buf[-64:], pos + len(b)
```

This gave many hits, including **uncompressed** copies of the latest version of the note, for example at `0xc8e5bf34` and `0x18f2678d2`. The IndexedDB record is `"data"` with the file key `...Develop ideas.md`:

```
1. AES or RSA ?
2. AES is faster but symmetric
3. RSA is slow but asymmetric
4. Maybe use both?



bu
	pct
		f{Str1
	ng5_
f41l
		ed_
	y0u
	_buT_
  i_g0T
		_yoU
}
```

## 4. Rebuilding the flag

Join the lines and strip the newlines, tabs and leading spaces:

```python
parts = ['bu', 'pct', 'f{Str1', 'ng5_', 'f41l', 'ed_', 'y0u', '_buT_', 'i_g0T', '_yoU', '}']
print(''.join(parts))
```

```
bupctf{Str1ng5_f41led_y0u_buT_i_g0T_yoU}
```

The flag reads "**Strings failed you, but I got you**". That is a direct reference to how `strings`/grep misses a flag that is split across lines.

## Takeaways

- **Don't search only for the flag prefix.** If the author breaks the flag up with whitespace, `strings | grep bupctf` finds only decoys. Search for text *next to* the secret instead, such as unique words from the same note.
- **Electron apps (Obsidian, VS Code, Discord…) keep data in LevelDB/IndexedDB.** On-disk and in-memory blocks are often Snappy-compressed. Literal runs survive, so a note looks "almost readable" with 1–3 byte gaps, which are the Snappy copy/literal tags.
- **Memory holds several versions of the same document.** The older version (`Str1ng5_fail`) was a trap. Check for the most complete, most recent copy.
- **Scan a 17 GB image in chunks** (`f.read(16 MB)` + `bytes.find`) instead of running a whole-file regex over `mmap`. The regex is slow, and the mmap version was killed when the machine ran low on memory.
