# Coverup

**Category:** rev | **Points:** 413 | **Flag:** `ENO{c0v3r4g3_l34k5_s3cr3t5_really_g00d_you_Kn0w?}`

## Overview
Given a PHP encryption script, its xdebug code coverage output, and the encrypted flag, recover the original plaintext.

## Solution
The encryption (`encrypt.php`) applies a 3-step process to each character:
1. **Key substitution** — each key byte maps through a 256-entry lookup table (`chr(N) + offset mod 256`)
2. **XOR** — plaintext XOR processed key
3. **Output substitution** — the XOR result maps through the same lookup table
4. Result is base64-encoded with a SHA1 checksum

The key is 9 random printable ASCII bytes. The critical leak is **xdebug code coverage** (`coverage.json`), which records which lines were executed. Since the lookup table is implemented as 256 sequential if/else branches, the coverage reveals:
- **Which key byte values were used** (9 branches hit in the key processing section)
- **Which XOR result values occurred** (40 branches hit in the output processing section)

The solve approach:
1. Parse the PHP to extract the substitution table (256 entries, non-bijective — 66 collisions)
2. Parse coverage to identify the 9 key chars and 40 XOR result values
3. Use known plaintext `ENO{` and `}` to fix 4 of 9 key positions
4. Brute force the remaining 5 positions (9^5 = 59,049 candidates)
5. For each key, resolve ambiguous sub_table inversions by trying all combinations and scoring for readable English

A few positions had 2 valid xored candidates (sub_table collisions), resolved by preferring the decryption that produces recognizable words: "good" over "goon", "you" over "sou".

## Key Takeaways
- Xdebug code coverage with branch-level granularity leaks which code paths were taken — if each value has its own branch, coverage = a value oracle.
- Non-bijective substitution tables create ambiguity during inversion, but known plaintext + English readability resolve it.
- Coverage side-channels are a real class of vulnerability in web applications with debug tooling enabled.
