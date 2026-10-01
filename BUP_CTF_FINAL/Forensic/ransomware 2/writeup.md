# Ransomware II — Writeup

**Category:** Forensics  
**Points:** 339  
**Author:** RayQuaZa

> i was listening to one of my recent favourite song during the execution of the ransomware. What is the name of it?

## Flag

```
bupctf{Ae_Ajnabee}
```

---

## Files

`ransomware.7z` holds a single file, `ransomware.raw`. It is a ~17.7 GB Windows 11 memory image.

```
$ 7z l ransomware.7z
2026-09-28 01:45:08 ....A  17703632896   4435923760  ransomware.raw
```

## 1. Process listing: where was the music coming from?

```
vol -f ransomware.raw windows.pslist
```

What the process list shows:

- **No dedicated media player** is running: no Spotify, VLC, Groove or Windows Media Player.
- **Brave is open.** The browser (`brave.exe`, PID 16460, plus its child processes) has been running since 18:14 UTC.
- **Suspicious processes** from the ransomware part of the challenge: `MRCv120.exe` (PID 26324, 18:32 UTC) and `claude.exe` (PID 19976, 19:44 UTC, just before the image was captured).
- **An audio session is active.** `audiodg.exe` (PID 7004) is running.

So the song was most likely playing in a browser tab, probably YouTube.

## 2. Searching memory for YouTube titles

YouTube tab titles look like `<video title> - YouTube`. I searched the raw image for that pattern in both ASCII and UTF-16LE. Windows window titles and accessibility strings are stored in UTF-16LE.

```bash
# ASCII (browser history / page data)
rg -a -o '[ -~]{3,100} - YouTube( Music)?' ransomware.raw | sort | uniq -c | sort -rn

# UTF-16LE (window titles, taskbar / UI Automation strings)
rg -a -o -E utf-16le '[ -~]{3,120} - (YouTube|Brave)[ -~]{0,40}' ransomware.raw | sort | uniq -c | sort -rn
```

UTF-16LE results (trimmed):

```
 24 Ae Ajnabee (Official Music Video) - Aditya Rikhari, Ravator, Kutle Khan | Coke Studio Bharat - YouTube
 23 Rick Astley - Never Gonna Give You Up (Official Video) (4K Remaster) - YouTube
 10 Chalo Door Kahin (Official Video) - Samar Jafri - YouTube
  9 Murtaza Qizilbash | Bhool | Official Audio - YouTube
  8 Anuv Jain X Lost Stories - Arz Kiya Hai (Official Video) | Coke Studio Bharat - YouTube
  7 Alfaaz | Hamza Malik x Zain Zohaib | Official Visualiser - YouTube
  5 rick roll - YouTube
  ...
  2 Ae Ajnabee (Official Music Video) - Aditya Rikhari, Ravator, Kutle Khan | Coke Studio Bharat - YouTube - Brave
  1 le Khan | Coke Studio Bharat - YouTube - Audio playing
  1 Coke Studio Bharat - YouTube - Brave - 1 running window
```

The memory contains a whole YouTube radio/playlist history, so a list of titles alone doesn't answer the question. We need to know which tab was **actually playing audio**.

## 3. Finding the tab that was playing

Three UTF-16 strings answer that:

1. **Brave's window title**
   `Ae Ajnabee (Official Music Video) - ... | Coke Studio Bharat - YouTube - Brave`
   Brave names its window after the active tab.

2. **The taskbar's accessibility text**
   `...Kutle Khan | Coke Studio Bharat - YouTube - Audio playing`
   The Windows 11 taskbar adds **"Audio playing"** to a button's name when that app is producing sound. This is the key artifact: it says which tab was playing.

3. **The taskbar button**
   `...Coke Studio Bharat - YouTube - Brave - 1 running window`

Supporting evidence:

- *Ae Ajnabee* is the most frequent YouTube title in memory: 24 UTF-16 hits plus 19 ASCII hits.
- The Rick Astley hits come from a `rick roll` search (`search_query=rick+roll`). It's a decoy.
- The other titles (Murtaza Qizilbash, Samar Jafri, Alfaaz, and so on) appear only in radio-playlist URLs (`list=RD...&index=N`) and search queries. None of them has a window title or an "Audio playing" marker.

## 4. Answer

The song playing while the ransomware ran:

**Ae Ajnabee** by Aditya Rikhari, Ravator and Kutle Khan (Coke Studio Bharat)

```
bupctf{Ae_Ajnabee}
```

## Takeaways

- If no media-player process is running, look at the browser. Window titles and taskbar UI Automation strings are UTF-16LE, so an ASCII-only `strings` pass misses them.
- The Windows 11 taskbar's **"- Audio playing"** suffix shows which window was producing sound when memory was captured.
- Don't answer with the most common or most obvious title (the Rick Roll). Confirm with a marker that shows the audio was actually playing.
