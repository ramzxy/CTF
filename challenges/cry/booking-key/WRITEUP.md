# Booking Key - Writeup

**Category:** cry | **Points:** 491 | **Solves:** 4

## Flag

```
ENO{y0u_f1nd_m4ny_th1ng5_in_w0nd3r1and}
```

## Analysis

This is a **book cipher** challenge. The encryption works as follows:

1. A random starting position `key` is chosen in the book (Alice in Wonderland)
2. A 32-character password is generated from letters present in the book
3. For each character in the password:
   - Count how many positions you need to move forward in the book to find that character
   - Append the count to the cipher array
   - Current position becomes where the character was found

We need to decode 3 passwords correctly to get the flag.

## Solution

Since we know the book and the cipher (list of offsets), we can **brute force** all possible starting positions (0 to len(book)-1). For each starting position, we decrypt and check if all characters are valid letters (exist in the charset).

The key insight is that while there may be multiple valid starting positions that produce letter-only output, one of them is the correct password. Since the server randomizes passwords each connection, we can simply retry until we get lucky with our guess.

## Solve Script

```python
from pwn import *
import ast
import string

def decrypt(cipher, book, start):
    current = start
    plaintext = []
    for count in cipher:
        current = (current + count) % len(book)
        plaintext.append(book[current])
    return ''.join(plaintext)

def solve_for_key(cipher, book, charset):
    valid_solutions = []
    for start in range(len(book)):
        plaintext = decrypt(cipher, book, start)
        if all(c in charset for c in plaintext):
            valid_solutions.append((start, plaintext))
    return valid_solutions

BOOK = open('book.txt', 'r').read()
charset = set(c for c in string.ascii_letters if c in BOOK)

for attempt in range(100):
    r = remote('52.59.124.14', 5102)
    r.recvline()

    success = True
    for round_num in range(3):
        cipher = ast.literal_eval(r.recvline().decode().strip())
        solutions = solve_for_key(cipher, BOOK, charset)
        password = solutions[0][1]  # Take first valid solution

        r.recvuntil(b'password: ')
        r.sendline(password.encode())

        if r.recvline().decode().strip() != 'correct':
            success = False
            break

    if success:
        print(r.recvline().decode().strip())  # FLAG
        break
    r.close()
```
