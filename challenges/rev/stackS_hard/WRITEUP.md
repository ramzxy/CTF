# stackS (hard)

**Category:** rev | **Flag:** `ENO{W0W_D1D_1_JU5T_UNLUCK_4_N3W_SK1LL???}`

## Overview
Harder variant of the stackS binary with the same stack-strings pattern but a more complex cipher loop involving table lookups and a chained accumulator.

## Solution
Same overall structure as the medium version (mmap + memcpy + XOR stack strings), but the cipher adds two layers:

1. **Permuted table lookup** — Instead of checking `input[i]` directly, a second keystream (`edx ^ 0xec8804a0`) XOR'd with stored data at offset 0xA2 computes an *index* into the input buffer. The character at that index is used for the comparison.

2. **Rolling accumulator** — A byte `bl` initialized from `buf[0xF9] ^ 0x77` is ROL'd by 1 and added to the encrypted input byte each iteration, chaining all checks together.

A third keystream (`edx ^ 0x19e0463b`) XOR'd with stored data at offset 0xCB provides the target value.

Since the initial accumulator is known and each iteration reveals `input[index]`, the solve is sequential: compute index and target from keystreams, solve for the input byte, update the accumulator, repeat.

## Key Takeaways
- Table-lookup permutations look scary but don't add cryptographic strength when the index mapping is deterministic from known data.
- Chained accumulators (where iteration N depends on N-1) force sequential solving but don't prevent it — the chain unrolls from the known initial state.
- Reusing the same solver skeleton from an easier variant and layering on the new operations saves time.
