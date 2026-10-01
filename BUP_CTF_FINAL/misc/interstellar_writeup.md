# Interstellar — BUP CTF Final (Misc, 365 pts, 8 solves)

**Author:** Anon_47
**File:** `interstellar/interstellar.mp4`
**Status:** the Morse message below is certain, but `bupctf{lov3_is_da_fif7h_dim3ntion_uwu}` was **rejected** by the platform.
Morse carries no case, braces or separators, so the exact format is still unconfirmed. Candidates to try, most likely first:
1. `bupctf{LOV3_IS_DA_FIF7H_DIM3NTION_UWU}`
2. `bupctf{lov3isdafif7hdim3ntionuwu}` / `bupctf{LOV3ISDAFIF7HDIM3NTIONUWU}`
3. `BUPCTF{LOV3_IS_DA_FIF7H_DIM3NTION_UWU}`
4. `bupctf{th3_tr4v3l_4cr0ss_sp4c3_4nd_t1m3_c0nt1nu3s}` (the frame-415 Base64, in case it isn't a decoy)

These were checked and **ruled out** as hiding anything else: every frame of each scene (object counts are stable, no off-screen ships, and O is never 0), hidden single frames, the dark and black segments, packet timing (constant 25 fps, keyframe every 25 frames), per-scene attributes that could encode case (size, ship direction, duration), and the audio spectrogram.

> Three ships set out on humanity's final interstellar voyage. [...] he transmitted one last
> message back to his daughter on Earth: an odd time-lapse capturing their entire voyage
> across distant planets and galaxies.
> Can you solve the equation, extract the quantum truth, and save human civilization?

## TL;DR
The video is a slideshow of scenes with **planets** (round, spiky blobs) and **ships** (long rockets).
Read left to right, each scene is one Morse character: **planet = dot, ship = dash**.
That's a nod to the film, where Cooper sends Murph the "quantum data" in Morse code from inside the tesseract.
The 31 scenes spell `BUPCTF LOV3 IS DA FIF7H DIM3NTION UWU`.
The video also has two decoy flags.

## 1. Recon

```
$ ffprobe -show_format -show_streams interstellar.mp4
  h264 1920x1080 @ 25 fps, 1304 frames, 52.16 s  |  aac stereo 44.1 kHz
  TAG:comment=bupctf{th3_v0y4g3_1s_f4r_fr0m_0v3r}
```

**Decoy #1.** The metadata comment is a flag that literally says *"the voyage is far from over"*.

I walked the MP4 boxes (`ftyp / free / mdat / moov / udta`). There's no trailing data and no unusual boxes, so nothing is carved or appended.

## 2. The "odd time-lapse"

I downscaled every frame and plotted mean brightness and frame-to-frame difference. The video is a sequence of
**fade-in → hold → fade-out** scenes over a dark topographic-contour background. There are 31 object scenes plus one dim text scene at frames 408–420.

A contact sheet of one frame per scene showed:

* **Frame 415:** a line of text (plus its mirrored reflection):
  ```
  YnVwY3Rme3RoM190cjR2M2xfNGNyMHNzX3NwNGMzXzRuZF90MW0zX2MwbnQxbnUzc30=
  → bupctf{th3_tr4v3l_4cr0ss_sp4c3_4nd_t1m3_c0nt1nu3s}
  ```
  **Decoy #2.** It says *"the travel continues"*.
* **Every other scene:** a different mix of planets and ships.

The audio spectrogram and the L−R channel difference were plain music with nothing hidden, and the background-only frames were clean contour art after contrast boosting.

## 3. Solving the equation: planets and ships as Morse code

Frame 563 has three planets on the left and two ships on the right: `...--` = **3**.
Applying that rule to every scene:

| Scene frames | Objects (L→R) | Char |
|---|---|---|
| 86–125 | `-...` | B |
| 132–172 | `..-` | U |
| 181–220 | `.--.` | P |
| 227–267 | `-.-.` | C |
| 274–311 | `-` | T |
| 320–361 | `..-.` | F |
| 462–491 | `.-..` | L |
| 496–522 | `---` | O |
| 527–552 | `...-` | V |
| 556–583 | `...--` | 3 |
| 587–613 | `..` | I |
| 619–645 | `...` | S |
| 650–676 | `-..` | D |
| 681–707 | `.-` | A |
| 711–738 | `..-.` | F |
| 744–773 | `..` | I |
| 777–806 | `..-.` | F |
| 810–833 | `--...` | 7 |
| 837–862 | `....` | H |
| 868–893 | `-..` | D |
| 899–924 | `..` | I |
| 932–954 | `--` | M |
| 962–988 | `...--` | 3 |
| 994–1016 | `-.` | N |
| 1025–1042 | `-` | T |
| 1055–1072 | `..` | I |
| 1084–1106 | `---` | O |
| 1113–1142 | `-.` | N |
| 1149–1175 | `..-` | U |
| 1181–1204 | `.--` | W |
| 1211–1235 | `..-` | U |

```
BUPCTF LOV3 IS DA FIF7H DIM3NTION UWU
```

This also fits the theme: *"Love is the one thing we're capable of perceiving that transcends dimensions of time and space"*, and the tesseract is the 5th-dimensional construct.
Morse has no case, braces or underscores, so the flag is wrapped in the standard format:

```
bupctf{lov3_is_da_fif7h_dim3ntion_uwu}
```

## 4. Automation (`interstellar/solve.py`)

1. Decode all frames to grayscale with ffmpeg (half resolution).
2. Segment scenes as runs of frames with mean brightness > 3. The dark text scene falls below this, so it drops out.
3. For each scene, take the brightest frame, threshold it (> 120), and dilate it so a rocket body joins its exhaust flame. Then label connected components.
4. Classify each object by the ratio of its principal axes (from the covariance eigenvalues): ≈1 → planet (`.`), ≈6 → ship (`-`).
5. Sort by x, map to Morse, and join.

```
$ python solve.py
...
Morse message: BUPCTFLOV3ISDAFIF7HDIM3NTIONUWU
Flag: bupctf{lov3_is_da_fif7h_dim3ntion_uwu}
```

## Takeaways
* A flag-shaped string in metadata or plain Base64 is usually a decoy when its text says "keep going".
* In "video time-lapse" challenges, segment the video into scenes first (brightness/difference curves), then look at one frame per scene.
* Themed hints matter: in *Interstellar*, the message is sent to Murph in **Morse code**.
