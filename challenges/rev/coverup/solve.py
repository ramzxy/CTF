#!/usr/bin/env python3
"""Solve the coverup challenge using coverage data to recover the key."""

import re
import json
import base64
from itertools import product

# Step 1: Extract the substitution table from encrypt.php
with open("files/encrypt.php") as f:
    code = f.read()

sub_table = {}
for m in re.finditer(
    r'if \(\$keyChar == chr\((\d+)\)\).*?\$processedKeyAscii = ord\(\$keyChar\) \+ (\d+);',
    code, re.DOTALL
):
    n, offset = int(m.group(1)), int(m.group(2))
    sub_table[n] = (n + offset) % 256

inv_table = {}
for k, v in sub_table.items():
    inv_table.setdefault(v, []).append(k)

# Step 2: Parse coverage.json
with open("files/output/coverage.json") as f:
    coverage = json.load(f)

cov_lines = list(coverage.values())[0]["lines"]

key_chars_used = set()
xored_vals_used = set()

for n in range(256):
    if cov_lines.get(str(47 + n * 6), -1) == 1:
        key_chars_used.add(n)
    if cov_lines.get(str(1591 + n * 6), -1) == 1:
        xored_vals_used.add(n)

print(f"Key chars used ({len(key_chars_used)}): {sorted(key_chars_used)}")
print(f"  As chars: {''.join(chr(c) for c in sorted(key_chars_used))}")
print(f"XOR values used ({len(xored_vals_used)}): {sorted(xored_vals_used)}")

# Step 3: Decode encrypted output
with open("files/output/encrypted_flag.txt") as f:
    encrypted_line = f.read().strip()

b64_data, checksum = encrypted_line.split(":", 1)
encrypted_bytes = base64.b64decode(b64_data)
flag_len = len(encrypted_bytes)
print(f"Flag length: {flag_len}")

# Step 4: Find xored candidates per position (filtered by coverage)
xored_candidates = []
for eb in encrypted_bytes:
    all_inv = inv_table.get(eb, [])
    filtered = [x for x in all_inv if x in xored_vals_used]
    xored_candidates.append(filtered if filtered else all_inv)

# Step 5: Determine fixed key bytes from known plaintext ENO{...}
known_plain = {0: ord('E'), 1: ord('N'), 2: ord('O'), 3: ord('{')}
known_plain[flag_len - 1] = ord('}')

fixed_key = {}
for pos, plain_byte in known_plain.items():
    key_pos = pos % 9
    valid_keys = set()
    for xored_val in xored_candidates[pos]:
        pk = xored_val ^ plain_byte
        for k in inv_table.get(pk, []):
            if k in key_chars_used:
                valid_keys.add(k)
    if len(valid_keys) == 1:
        fixed_key[key_pos] = list(valid_keys)[0]

print(f"Fixed key: { {kp: chr(k) for kp, k in fixed_key.items()} }")

# Step 6: Brute force remaining positions
# For each key combo AND each xored ambiguity combo, find best flag
unconstrained = [kp for kp in range(9) if kp not in fixed_key]
key_list = sorted(key_chars_used)

print(f"Unconstrained: {unconstrained}, search: {len(key_list)**len(unconstrained)}")

best_score = -9999
best_flag = None
best_key_str = None
top_results = []

for combo in product(*[key_list for _ in unconstrained]):
    key_bytes = [0] * 9
    for kp, k in fixed_key.items():
        key_bytes[kp] = k
    for kp, k in zip(unconstrained, combo):
        key_bytes[kp] = k

    pk = [sub_table[k] for k in key_bytes]

    # For each position, find all printable plaintext options
    pos_options = []
    any_impossible = False
    for i in range(flag_len):
        options = []
        for xored_val in xored_candidates[i]:
            pb = xored_val ^ pk[i % 9]
            if 32 <= pb <= 126:
                options.append(pb)
        if not options:
            any_impossible = True
            break
        pos_options.append(options)

    if any_impossible:
        continue

    # Find ambiguous positions for THIS key
    ambig_indices = [i for i, opts in enumerate(pos_options) if len(opts) > 1]

    if len(ambig_indices) > 12:
        # Too many ambiguities, skip
        continue

    # Try all combos of ambiguous positions
    ambig_choices = [pos_options[i] for i in ambig_indices]
    if ambig_choices:
        choices_iter = product(*ambig_choices)
    else:
        choices_iter = [()]

    for achoice in choices_iter:
        plaintext = []
        for i in range(flag_len):
            if i in ambig_indices:
                plaintext.append(achoice[ambig_indices.index(i)])
            else:
                plaintext.append(pos_options[i][0])

        text = bytes(plaintext).decode('ascii', errors='replace')
        if not (text.startswith("ENO{") and text.endswith("}")):
            continue

        # Score: flag content (between ENO{ and }) prefers lowercase, digits, _
        inner = text[4:-1]  # strip ENO{ and }
        score = 0
        for c in inner:
            if c.islower() or c.isdigit() or c == '_':
                score += 3
            elif c.isupper():
                score += 1
            else:
                score -= 5
        if score >= best_score - 10:
            top_results.append((score, text, ''.join(chr(c) for c in key_bytes)))
        if score > best_score:
            best_score = score
            best_flag = text
            best_key_str = ''.join(chr(c) for c in key_bytes)

top_results.sort(key=lambda x: -x[0])
print(f"\nTop 10 results:")
for sc, fl, ky in top_results[:10]:
    print(f"  [{sc}] key={ky} -> {fl}")

print(f"\nBest Flag: {best_flag}")

with open("flag.txt", "w") as f:
    f.write(best_flag + "\n")
