# Seen - Writeup

**Points:** 68  
**Solves:** 145

## Challenge Analysis

The challenge provided an HTML file `index.html` containing JavaScript. The key difficulty was decoding a large string `s` made of Unicode variation selectors `\uFE00` to `\uFE0F`.

## Solution

The JavaScript code decoded pairs of variation selectors from `s` into a byte array `t` of length 72.

- The flag length was verified to be exactly half of `t`'s length: 36.
- The verification logic uses a generator function `gen` which updates based on the input character and compares the result with `t[36 + i]`.
- This means the correctness of character $i$ can be verified using the generator state from step $i-1$.

## Exploit

We could brute-force the flag one character at a time:

1. Initialize `gen = 0x10231048`.
2. For each position `i` from 0 to 35:
   - Try every ASCII character.
   - Compute the next `gen` state and check if `(gen % 256 + 256) % 256` equals `t[36 + i]`.
   - If it matches, append the character and update `gen`.

**Flag:** `ENO{W0W_1_D1DN'T_533_TH4T_C0M1NG!!!}`
