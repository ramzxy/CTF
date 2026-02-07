#!/usr/bin/env python3
"""
Solver for the 'Seen' misc challenge - character by character brute force.

The algorithm:
- t[] contains 72 bytes (36 pairs of 4-bit nibbles)
- The flag is 36 characters
- gen starts at 0x10231048
- For each char: gen = ((gen ^ 0xA7012948 ^ char) + 131203) & 0xFFFFFFFF
- t[36+i] must equal (gen % 256 + 256) % 256

We can brute-force character by character since each position only depends
on the previous gen state.
"""

import re

# Read the string directly from the HTML file
with open('files/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

match = re.search(r'const s="([^"]+)"', content)
s = match.group(1)

vs = 0xFE00

# Decode the variation selectors into bytes
t = []
for i in range(0, len(s), 2):
    c1 = ord(s[i])
    c2 = ord(s[i+1])
    byte_val = ((c1 - vs) << 4) | (c2 - vs)
    t.append(byte_val & 0xFF)

print(f"Decoded {len(t)} bytes")
flag_len = len(t) // 2
print(f"Flag length: {flag_len}")
print(f"Verification bytes (second half): {t[flag_len:]}")

# Brute force the flag character by character
flag = []
gen = 0x10231048

for i in range(flag_len):
    expected = t[flag_len + i]
    found = False
    
    for char in range(256):  # Try all possible byte values
        test_gen = ((gen ^ 0xA7012948 ^ char) + 131203) & 0xFFFFFFFF
        computed = (test_gen % 256 + 256) % 256
        
        if computed == expected:
            flag.append(char)
            gen = test_gen
            found = True
            break
    
    if not found:
        print(f"No valid char found for position {i}")
        break

print(f"\nFlag bytes: {bytes(flag)}")
print(f"Flag: {bytes(flag).decode('utf-8', errors='replace')}")

# Verify
u = flag
gen = 0x10231048
for i in range(len(u)):
    gen = ((gen ^ 0xA7012948 ^ u[i]) + 131203) & 0xffffffff
    expected = t[len(u) + i]
    computed = (gen % 256 + 256) % 256
    if expected != computed:
        print(f"Verification failed at {i}")
        break
else:
    print("\n✓ Flag verified!")
