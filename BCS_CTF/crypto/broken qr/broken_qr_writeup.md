# Broken QR Writeup

## Challenge

The challenge provides `qr.txt`, which contains space-separated 8-bit binary
values instead of a normal QR image.

The goal is to recover the flag.

## Step 1: Convert Binary Bytes to Text

Each value in `qr.txt` is an ASCII byte written in binary.

Decoding the binary bytes gives:

```text
y5ewA6Je6gmLvTRHwUenpGxNQZyMy8vqwPUQbTfK6MMdXvZJbJWM52quijpaggQZ1FYELnC
```

This string is not normal Base64. Its alphabet matches Base58.

## Step 2: Base58 Decode

Base58-decoding the string gives valid UTF-8 bytes. The decoded text is made of
large Unicode codepoints, which looks strange at first:

```text
\u9862\u9873\u9b74\u7d7b\ua333\u946c\u654e\u9421\u9d37\u6a31\u655f\u686e\u665f\u9435\ua366\u9c34\U00020321
```

This is the trick: each Unicode codepoint hides two useful bytes.

## Step 3: Split Codepoints Into Two Streams

For every decoded Unicode codepoint:

- the low byte gives one flag character
- the high byte is offset by `0x35`; subtracting `0x35` gives the next flag
  character

Interleaving those recovered characters gives:

```text
bcsctf{H3nl_N0!_7h15_0n3_15_fn4g!Î
```

This is almost the full flag, but the QR was intentionally broken.

## Step 4: Repair the Broken Characters

The recovered text already matches the known flag format `bcsctf{...}` and is a
clear leetspeak sentence. The broken parts are obvious OCR-style corruptions:

```text
H3nl  -> H3ll
fn4g  -> fl4g
Î     -> }
```

After repairing those corrupted characters, the final flag is:

```text
bcsctf{H3ll_N0!_7h15_0n3_15_fl4g!}
```

## Solver

The included `solve.py` performs the full recovery:

1. Read `qr.txt`.
2. Convert binary bytes to ASCII.
3. Base58-decode the result.
4. Decode the bytes as UTF-8.
5. Split each codepoint into low/high byte characters.
6. Apply the final corruption repair.

Running it prints:

```text
bcsctf{H3ll_N0!_7h15_0n3_15_fl4g!}
```
