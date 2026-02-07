# Going in Circles - Writeup

**Category:** Crypto
**Description:** Polynomial arithmetic over GF(2) and CRT.
**Flag:** `ENO{CRC_is_just_some_modular_remainder}`

## Overview

The challenge provides a server that returns $P(x) \pmod{m_i(x)}$ where $P$ is the flag polynomial and $m_i$ are random 32-bit polynomials over GF(2).

## Solution

This is a standard Chinese Remainder Theorem (CRT) problem, but over GF(2)[x] instead of integers.
Since the random moduli $m_i$ are not necessarily pairwise coprime, we used an **Incremental CRT** approach.

1.  **GF(2) Arithmetic**: Implemented custom `mul`, `div`, `gcd`, `inv` using bitwise operations (XOR for addition/subtraction).
2.  **Constraint Merging**: For each new congruence $x \equiv r \pmod m$, we merged it with the current solution $X \pmod M$ by checking consistency with $g = \gcd(M, m)$ and updating the modulus to $\text{lcm}(M, m)$.
3.  **Data Collection**: Connected to the server repeatedly until the total degree of combined moduli covered the flag size (~600 bits).

## Key Takeaways

- Polynomial arithmetic over GF(2) is just XOR and bit shifts.
- Incremental CRT can handle non-coprime moduli by checking consistency on the GCD.
- `sage` or `pwntools` were not needed; pure Python bitwise ops suffice.
