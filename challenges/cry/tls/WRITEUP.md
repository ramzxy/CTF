# TLS

**Category:** cry
**Points:** 410
**Solves:** 31

## Description

The challenge implements a custom "TLS" protocol where the flag is encrypted with AES-128-CBC using a random key. The key itself is encrypted using RSA-1337.

The service acts as a padding oracle (specifically a range oracle) regarding the decrypted RSA value:

- If the decrypted RSA integer is $\ge 2^{128}$, it returns "something else went wrong".
- If the decrypted RSA integer is $< 2^{128}$, it attempts AES decryption and usually returns "invalid padding".

## Solution

The vulnerability allows us to determine if a decrypted RSA message $m$ is greater than or equal to $2^{128}$. Since the AES key is generated with `bytes(8) + os.urandom(8)`, the valid key $K$ is strictly less than $2^{64}$.

We can perform a binary search to find the value of $m$ (the AES key). By multiplying the ciphertext $C$ by $s^e \pmod N$, the decrypted value becomes $m' = m \cdot s \pmod N$.

We search for the smallest multiplier $s$ such that $m \cdot s \ge 2^{128}$.
Once found, we can approximate the key as $K = \lfloor 2^{128} / s \rfloor$.

### Script

The solution script `files/solve.py` implements this binary search.

1. Connects to the service.
2. Extracts $N$ and the ciphertext.
3. Performs binary search for $s$ in the range $[2^{64}, 2^{128}]$.
4. Recovers the AES key.
5. Decrypts the flag.

## Flag

`ENO{Y4y_a_f4ctor1ng_0rac13}`
