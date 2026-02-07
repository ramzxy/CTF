#!/usr/bin/env python3
"""
Solver for the 'Emoji' misc challenge.
"""

import zipfile

with zipfile.ZipFile('files/chall.zip', 'r') as z:
    content = z.read('README.md')

print(f"Raw bytes ({len(content)} bytes):")
print(content)
print()

# Decode as UTF-8
text = content.decode('utf-8')
print(f"Text length: {len(text)} characters")

# Extract tag characters (U+E0000 to U+E007F map to ASCII)
TAG_BASE = 0xE0000

flag_chars = []
for c in text:
    code = ord(c)
    if 0xE0001 <= code <= 0xE007F:
        ascii_val = code - TAG_BASE
        flag_chars.append(chr(ascii_val))

print(f"\nExtracted {len(flag_chars)} tag characters")
print(f"Flag: {''.join(flag_chars)}")
