#!/usr/bin/env python3
"""Solve the stackS_hard reverse engineering challenge."""

# Initial data from rodata at 0x20e0 (0xfa bytes)
buf = bytearray(bytes.fromhex(
    "e0f31adbc6417e8961fb2e9401d0a3b5"
    "83f9ff37112c2ddf2c4c3259e257414f"
    "cacad8c2360730c0acd52f39dc946368"
    "35ea43831f1ba0498968f8bac1af8dee"
    "9955dfffed6702d188d7b380cea3c00f"
    "a809f4677bfa5983c4a61f93000400f4"
    "1a0ad7a0748f46e3a4a6281c0bb22076"
    "38695ec54f3a8e33af95536d9ead8dc1"
    "b60a4df588fe987dc9372c6f1626fbfe"
    "83e8ca24c5a2d4696967e8c686f300c7"
    "a0efb229e219ffb80bc2607d9c7a3824"
    "cab9a34e51f27ec05bae0ddb9c9e85c4"
    "7d75ff5361532be854988f98bfbfc76d"
    "0f4a848a2db0c883d38a639712f5cac4"
    "0e891bbcdc487ac20deb72e8e5397395"
    "50609d098ea7a1a1efab"
))

# Extract key values from buf
# rbx = buf[0xf4] ^ 0xa7 (expected input length)
expected_len = buf[0xf4] ^ 0xa7
print(f"Expected input length: {expected_len}")

# r15d = (buf[0xf8]^0x13)<<24 | (buf[0xf7]^0x4b)<<16 | (buf[0xf6]^0xd3)<<8 | (buf[0xf5]^0x3a)
a = buf[0xf5] ^ 0x3a
c = buf[0xf6] ^ 0xd3
d = buf[0xf7] ^ 0x4b
r15 = buf[0xf8] ^ 0x13
c = (c << 8) | a
d = (d << 16) | c
r15 = (r15 << 24) | d
r15 = r15 & 0xFFFFFFFF
print(f"r15d: 0x{r15:08x}")

# r13b initial = buf[0xf9] ^ 0x77
r13_init = buf[0xf9] ^ 0x77
print(f"r13b initial: 0x{r13_init:02x}")

# Stored data arrays
stored1 = buf[0xa2:]  # stored1[i] = buf[0xa2 + i], used for index computation
stored2 = buf[0xcb:]  # stored2[i] = buf[0xcb + i], used for target computation
print(f"stored1 (at 0xa2): {stored1[:expected_len].hex()}")
print(f"stored2 (at 0xcb): {stored2[:expected_len].hex()}")

def rol32(val, n):
    n = n % 32
    val = val & 0xFFFFFFFF
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

def rol8(val, n):
    n = n % 8
    val = val & 0xFF
    return ((val << n) | (val >> (8 - n))) & 0xFF

# Cipher loop reconstruction
# For each iteration i:
#   Keystream B1 (index computation):
#     esi = edx ^ 0xec8804a0, ROL by (i & 7)
#     esi = hash(esi), then sil ^= stored1[i]
#     => index = sil & 0xff
#
#   Keystream B2 (target computation):
#     eax = edx ^ 0x19e0463b, ROL by (i & 7)
#     eax = hash(eax), then al ^= stored2[i]
#     => target = al & 0xff
#
#   Table lookup: r13d = input[index]
#
#   Keystream A:
#     esi = r10d ^ r15d, ROL by (r9d & 7)
#     hash(esi), then sil ^= input[index] (= r13d)
#     => computed = sil & 0xff
#
#   Check: ROL8(r13_prev, 1) + computed == target (mod 256)
#   => input[index] = keyA_raw ^ ((target - ROL8(r13_prev, 1)) & 0xff)
#
# Where keyA_raw is the keystream A value BEFORE XOR with input[index]

r10 = 0xa97288ed
edx = 0x9e3779b9
r9d = 0
r13_prev = r13_init

input_buf = [None] * 256  # will fill in as we discover

for i in range(expected_len):
    cl = i & 7

    # Keystream B1: compute index
    esi = edx ^ 0xec8804a0
    esi = esi & 0xFFFFFFFF
    esi = rol32(esi, cl)
    eax = (esi >> 16) & 0xFFFFFFFF
    eax = eax ^ esi
    eax = eax & 0xFFFFFFFF
    esi = (eax >> 8) & 0xFFFFFFFF
    esi = esi ^ eax
    esi = esi & 0xFFFFFFFF
    index = (esi & 0xFF) ^ stored1[i]

    # Keystream B2: compute target
    eax2 = edx ^ 0x19e0463b
    eax2 = eax2 & 0xFFFFFFFF
    eax2 = rol32(eax2, cl)
    ecx = (eax2 >> 16) & 0xFFFFFFFF
    ecx = ecx ^ eax2
    ecx = ecx & 0xFFFFFFFF
    eax2 = (ecx >> 8) & 0xFFFFFFFF
    eax2 = eax2 ^ ecx
    eax2 = eax2 & 0xFFFFFFFF
    target = (eax2 & 0xFF) ^ stored2[i]

    # Keystream A: compute raw keystream (before XOR with input)
    esi_a = r10 ^ r15
    esi_a = esi_a & 0xFFFFFFFF
    cl2 = r9d & 7
    esi_a = rol32(esi_a, cl2)
    ecx_a = (esi_a >> 15) & 0xFFFFFFFF
    ecx_a = ecx_a ^ esi_a
    ecx_a = ecx_a & 0xFFFFFFFF
    esi_a = (ecx_a >> 7) & 0xFFFFFFFF
    esi_a = esi_a ^ ecx_a
    esi_a = esi_a & 0xFFFFFFFF
    keyA_raw = esi_a & 0xFF

    # Solve: ROL8(r13_prev, 1) + (keyA_raw ^ input[index]) == target (mod 256)
    # => keyA_raw ^ input[index] = (target - ROL8(r13_prev, 1)) & 0xFF
    # => input[index] = keyA_raw ^ ((target - ROL8(r13_prev, 1)) & 0xFF)
    needed = (target - rol8(r13_prev, 1)) & 0xFF
    char_val = keyA_raw ^ needed

    input_buf[index] = char_val
    r13_prev = char_val  # r13d = input[index] for next iteration

    # Update loop counters
    r10 = (r10 + 0x85ebca6b) & 0xFFFFFFFF
    edx = (edx + 0x9e3779b9) & 0xFFFFFFFF
    r9d = (r9d + 3) & 0xFFFFFFFF

# Reconstruct the flag from input_buf
flag = bytes(input_buf[i] for i in range(expected_len))
print(f"\nRecovered input: {flag}")
try:
    decoded = flag.decode()
    print(f"As string: {decoded}")
    if decoded.startswith("ENO{"):
        print(f"Flag: {decoded}")
    else:
        print(f"Flag: ENO{{{decoded}}}")
except:
    print(f"Raw bytes: {flag.hex()}")
