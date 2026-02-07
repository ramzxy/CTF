# Matrixfun 2 - Writeup

**Category:** Crypto
**Description:** Affine Cipher over $\mathbb{Z}_{65}$, solved via Chosen Plaintext Attack.
**Flag:** `ENO{l1ne4r_alg3br4_i5_ev3rywh3re}`

## Overview

We are given an encryption oracle that maps messages to a custom alphabet of size 65. The encryption process uses a linear transformation:
$E(m) = Am + b \pmod{65}$
where $m$ is a 16-element vector derived from the input, and $A$ is a random 16x16 matrix.

## Solution

The encryption function boils down to an affine cipher $y = Ax + b$. Since we have an oracle, we can perform a **Chosen Plaintext Attack (CPA)** to recover $A$ and $b$.

1.  **Algebraic Structure**: Since $65 = 5 \times 13$, we can solve the system modulo 5 and modulo 13 separately and then combine the results using the **Chinese Remainder Theorem (CRT)**.

2.  **Data Collection**: We generated random input vectors $x_i$ and obtained their encryptions $y_i$. By considering the differences:
    $$ y*i - y_0 = A(x_i - x_0) \pmod{65} $$
    We constructed a linear system $Y*{\Delta} = A X\_{\Delta}$.

3.  **Key Recovery**: We collected enough pairs such that $X_{\Delta}$ was invertible. We computed $A$ by solving the system modulo 5 and 13:
    $$ A \equiv Y*{\Delta} X*{\Delta}^{-1} \pmod m $$
    Then we reconstructed $A$ modulo 65 using CRT. Once $A$ was known, $b$ was recovered using any $(x, y)$ pair.

4.  **Decryption**: We inverted the affine transformation to decrypt the flag using the recovered key:
    $$ x = A^{-1}(y - b) \pmod{65} $$
    The recovered base64 string decoded to the flag.

## Key Takeaways

- Affine ciphers are vulnerable to known/chosen plaintext attacks.
- Modular arithmetic with composite moduli can be handled by factoring into prime powers and using CRT.
- Random inputs are generally sufficient to generate a linearly independent set of vectors for key recovery.
