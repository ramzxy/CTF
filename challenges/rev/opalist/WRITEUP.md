# Opalist

**Category:** rev | **Flag:** `ENO{R3v_0p4L_4_FuN!}`

## Overview
Program written in OPAL (Optimized Applicative Language) that transforms input and outputs base64. Given the source code and the program's output, recover the original input.

## Solution
The OPAL program (`challenge_final.impl`) applies a pipeline to the input string:

1. **f1/f3** — Substitution cipher mapping each ASCII byte to another
2. **f4** — Converts characters to a nat sequence (ASCII codes)
3. **f8** — Adds a cumulative shift S to every element mod 256. S depends on each original byte's parity: `q_l = l` if even, `q_l = -l mod 256` if odd
4. **f13** — Standard Base64 encoding

The output was `YnpYZVeGc45lc2VUZ05h`. To reverse:

1. Base64 decode to 15 bytes
2. Brute-force the shift S (0–255), checking self-consistency — only S=27 satisfies the parity constraint
3. Invert the substitution cipher to recover `R3v_0p4L_4_FuN!`

## Key Takeaways
- OPAL is a rare functional language from TU Berlin — recognizing it from the `.impl`/`.sign` file extensions and syntax was key.
- When a cipher's total shift is a single value applied uniformly, brute-forcing 256 candidates is instant.
- The self-consistency check (shift depends on the data it produces) narrows 256 candidates to exactly one.
