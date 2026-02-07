# stackS (medium)

**Category:** rev | **Flag:** `ENO{1_L0V3_R3V3R51NG_5T4CK_5TR1NG5}`

## Overview
Stripped x86-64 ELF binary that reads input, encrypts it with a custom cipher, and compares against stored ciphertext. All strings are constructed at runtime via XOR ("stack strings").

## Solution
The binary mmaps a buffer, copies encrypted data from `.rodata`, and XOR-decrypts strings on the fly for I/O prompts. The core check is a cipher loop comparing each input byte:

- Two PRNG streams seeded with constants (`0xa97288ed` and `0x9e3779b9`), stepped with `+0x85ebca6b` and `+0x9e3779b9`
- Each stream is mixed via ROL/SHR/XOR to produce a keystream byte
- Stream A encrypts the user input; stream B decrypts the stored reference
- Match means correct character

Key parameters extracted from the buffer: expected length (offset 0xB8 XOR 0x36 = 35), 32-bit key r15d (offsets 0xB9–0xBC), and stored ciphertext at offset 0x95.

Reversing: compute both keystreams, XOR them together to recover each input byte directly.

## Key Takeaways
- "Stack strings" = strings built by XORing `.rodata` at runtime to avoid static `strings` detection.
- When two independent keystreams are compared, the input falls out as `keyA ^ keyB` — no brute force needed.
- Extract constants and data directly from the ELF rodata section by parsing section headers.
