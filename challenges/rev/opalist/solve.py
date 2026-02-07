#!/usr/bin/env python3
"""Reverse the OPAL challenge_final program to recover the flag."""

import base64

# f1: substitution cipher mapping (ASCII nat -> ASCII nat)
f1_map = {
    97: 83, 98: 117, 99: 67, 100: 98, 101: 116, 102: 36, 103: 96,
    104: 64, 105: 49, 106: 33, 107: 72, 108: 85, 109: 69, 110: 75,
    111: 119, 112: 107, 113: 86, 114: 78, 115: 48, 116: 99, 117: 76,
    118: 61, 119: 100, 120: 125, 121: 113, 122: 121,
    65: 106, 66: 118, 67: 58, 68: 103, 69: 65, 70: 57, 71: 89,
    72: 91, 73: 44, 74: 59, 75: 63, 76: 115, 77: 50, 78: 51,
    79: 77, 80: 55, 81: 101, 82: 71, 83: 92, 84: 39, 85: 46,
    86: 80, 87: 90, 88: 79, 89: 41, 90: 108,
    33: 70, 34: 62, 35: 87, 36: 120, 37: 40, 38: 123, 39: 34,
    40: 42, 41: 68, 42: 81, 43: 109, 44: 35, 45: 110, 46: 37,
    47: 54, 58: 97, 59: 84, 60: 112, 61: 66, 62: 114, 63: 122,
    64: 47, 91: 53, 92: 38, 93: 56, 94: 52, 95: 74, 96: 45,
    123: 102, 124: 126, 125: 104, 126: 43,
    48: 60, 49: 124, 50: 94, 51: 95, 52: 88, 53: 73, 54: 105,
    55: 111, 56: 82, 57: 93,
}

# Build inverse of f1
f1_inv = {v: k for k, v in f1_map.items()}

# Step 1: Base64 decode the output
output_b64 = "YnpYZVeGc45lc2VUZ05h"

# The program uses standard base64 (f9/f10/f11/f12/f13)
# But the output might not be standard base64 since values can be 0-255
# Let me decode manually using the same base64 alphabet

def b64_char_to_val(c):
    o = ord(c)
    if 65 <= o <= 90:  # A-Z
        return o - 65
    elif 97 <= o <= 122:  # a-z
        return o - 97 + 26
    elif 48 <= o <= 57:  # 0-9
        return o - 48 + 52
    elif o == 43:  # +
        return 62
    elif o == 47:  # /
        return 63
    elif o == 61:  # =
        return -1  # padding
    else:
        raise ValueError(f"Invalid base64 char: {c} (ord {o})")

def decode_b64_custom(s):
    """Decode base64 string to list of ints (0-255)."""
    result = []
    i = 0
    while i < len(s):
        chunk = s[i:i+4]
        vals = [b64_char_to_val(c) for c in chunk]

        if len(chunk) == 4:
            if vals[2] == -1:  # XX==
                b1 = (vals[0] << 2) | (vals[1] >> 4)
                result.append(b1)
            elif vals[3] == -1:  # XXX=
                b1 = (vals[0] << 2) | (vals[1] >> 4)
                b2 = ((vals[1] & 0xF) << 4) | (vals[2] >> 2)
                result.append(b1)
                result.append(b2)
            else:  # XXXX
                b1 = (vals[0] << 2) | (vals[1] >> 4)
                b2 = ((vals[1] & 0xF) << 4) | (vals[2] >> 2)
                b3 = ((vals[2] & 0x3) << 6) | vals[3]
                result.append(b1)
                result.append(b2)
                result.append(b3)
        i += 4
    return result

# Decode the output
decoded = decode_b64_custom(output_b64)
print(f"Base64 decoded ({len(decoded)} bytes): {decoded}")
print(f"As chars where printable: {''.join(chr(b) if 32 <= b <= 126 else f'[{b}]' for b in decoded)}")

# Step 2: Reverse f8
# f8 adds a total shift S to all elements, where S depends on original values' parity
# out[i] = (orig[i] + S) % 256
# S = sum_{l=0}^{n-1} q_l, where q_l = (l * p_l) % 256
# p_l = 1 if orig[l] is even, 255 (-1) if orig[l] is odd
# q_l = l if orig[l] even, (256-l) if orig[l] odd (for l>0, l=0 gives q=0 always)

# Brute force S from 0 to 255
n = len(decoded)

for S in range(256):
    # Compute candidate original values
    orig = [(b - S) % 256 for b in decoded]

    # Verify S is consistent
    total = 0
    for l in range(n):
        if orig[l] % 2 == 0:
            p = 1
        else:
            p = 255  # -1 mod 256
        q = (l * p) % 256
        total = (total + q) % 256

    if total != S:
        continue

    # Try to reverse f1 on each orig value
    plaintext = []
    valid = True
    for val in orig:
        if val in f1_inv:
            plaintext.append(chr(f1_inv[val]))
        else:
            valid = False
            break

    if valid:
        result = ''.join(plaintext)
        print(f"\nS={S}: {result}")
        print(f"Flag: ENO{{{result}}}")
