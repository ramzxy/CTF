# Hashinator

**Category:** rev | **Points:** 437 | **Flag:** `ENO{MD2_1S_S00_0ld_B3tter_Implement_S0m3Th1ng_ElsE!!}`

## Overview
Given a statically-linked OPAL binary that outputs hash chains, recover the flag from its OUTPUT.txt containing 54 hashes.

## Solution
The binary takes stdin and outputs `N+1` MD2-like hashes for an N-character input, where hash[i] = custom_hash(input[:i]).

1. **Identified MD2** — hash[0] = `8350e5a3e24c153df2275c9f80692773` = MD2(""). The first 16 hashes matched standard MD2 of the corresponding prefix.

2. **Recovered first 15 characters** — Used a pure-Python MD2 implementation to brute-force each character position, matching against OUTPUT.txt hashes. Recovered: `ENO{MD2_1S_S00_`.

3. **Hit the block boundary** — At position 16 (MD2's 16-byte block size), the binary's output diverged from standard MD2. The binary uses a custom/modified MD2 implementation (compiled from OPAL) that handles multi-block inputs differently. The standard S-box was not found directly in the binary data.

4. **Binary oracle approach** — Since the binary is executable, we used it as a black-box hash oracle. For each remaining position (16-53), tried all printable ASCII characters, ran the binary with the trial prefix, and compared the last hash against the target. ~95 trials per position, 38 positions = ~3,600 binary invocations.

## Key Takeaways
- When a binary is executable, use it as an oracle instead of fully reverse-engineering its internals.
- MD2 hash chains (hash of each prefix) allow character-by-character brute force since each position depends only on the prefix.
- The binary's MD2 implementation diverged from RFC 1319 at the block boundary — full reverse engineering would have been significantly harder than the oracle approach.
