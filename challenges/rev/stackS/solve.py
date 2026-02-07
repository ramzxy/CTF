#!/usr/bin/env python3
"""Solve the stackS reverse engineering challenge."""

import struct

# Initial data copied from rodata at 0x20d0 (0xbd bytes)
init_data = bytearray(bytes.fromhex(
    "ae6f23a82985f8b8326f01a8c41d38d3"
    "e96f877ab0c5b4ff61cb471e54ca8116"
    "b54ca4ad9db199eaf449024c335cf444"
    "293936e0e1dc7d3ad0e5dc81226655e3"
    "ba31fbfa98a7379fa6dcb60c25dfec87"
    "5d88d279a11131ee9dc76c95f2116956"
    "c6b192cdb4e83137a06f0e0bdc0a4dc6"
    "2f18e4a0f2defc0444faf78908526e97"
    "be2f557b4a2bf6a6ea72aad19f0d3abc"
    "31d2ee7626589266e7fbac56a91bb9af"
    "b81f08c74d33d0136825809b21556881"
    "1383f21d430853a0158aeb9ec2"
))

# XOR keys from rodata
xor_keys = {
    0x2010: bytes.fromhex("5203ea50f19dda400a7688867c42b288"),
    0x2020: bytes.fromhex("1da728d5a6d19611bf674e26a3ef62d0"),
    0x2030: bytes.fromhex("3e8490a0bbcd829169652351309d2a09"),
    0x2040: bytes.fromhex("5a5a8593b75d4eb195afa1560e30c3dd"),
    0x2050: bytes.fromhex("935203ea50f19dda400a7688867c42b2"),
    0x2060: bytes.fromhex("881da728d5a6d19611bf674e26a3ef62"),
    0x2070: bytes.fromhex("d03e8490a0bbcd829169652351309d2a"),
    0x2080: bytes.fromhex("095a5a8593b75d4eb195afa1560e30c3"),
    0x2090: bytes.fromhex("e3b2c26957ff81e230eab70b81725e8a"),
    0x20a0: bytes.fromhex("64bddc552f0f6021b7e5a937f982bf49"),
    0x20b0: bytes.fromhex("1b4321aed8e0bf9ec81b54cc0e6d60f6"),
    0x20c0: bytes.fromhex("000c856c5db7f3d299ae450aaeb2cd26"),
}

buf = bytearray(init_data)

# Step 1: movb $0x3d, (%r14)
buf[0] = 0x3d

# The program XORs the buffer to produce output strings and then XORs back.
# We don't need to simulate all the I/O, just the parts that affect the comparison.

# What matters for the flag:
# 1. r12d = buf[0xb8] XOR 0x36 (expected input length)
# 2. r15d = combined from buf[0xb9..0xbc] XOR'd with constants
# 3. The stored encrypted bytes at buf[0x95..] (after memcpy, before any XOR)
# 4. The cipher loop

# Extract r12 (expected length)
r12 = buf[0xb8] ^ 0x36
print(f"Expected input length (r12): {r12}")

# Extract r15d
# eax = buf[0xb9] ^ 0x19
# ecx = buf[0xba] ^ 0x95
# edx = buf[0xbb] ^ 0xc7
# r15d = buf[0xbc] ^ 0x0a
# ecx = ecx << 8 | eax
# edx = edx << 16 | ecx
# r15d = r15d << 24 | edx
a = buf[0xb9] ^ 0x19
c = buf[0xba] ^ 0x95
d = buf[0xbb] ^ 0xc7
r15 = buf[0xbc] ^ 0x0a
c = (c << 8) | a
d = (d << 16) | c
r15 = (r15 << 24) | d
r15 = r15 & 0xFFFFFFFF
print(f"r15d: 0x{r15:08x}")

# The stored encrypted data starts at offset 0x95 in buf (unmodified from init_data)
stored = buf[0x95:]
print(f"Stored data at 0x95 ({len(stored)} bytes): {stored[:r12].hex()}")

# Now reverse the cipher loop
# For each position i (0 to r12-1):
#   ebx_i = 0x9e3779b9 + i * 0x9e3779b9
#   eax_i = 0xa97288ed + i * 0x85ebca6b
#   r9d_i = i * 3
#
#   Keystream B (from ebx):
#     esi = ebx_i ^ 0xc19ef49e
#     cl = i & 7
#     esi = ROL32(esi, cl)  -- but it's ROL on full 32-bit register? Actually it's rol %cl, %esi
#     ecx = esi >> 16
#     ecx = ecx ^ esi
#     esi = ecx >> 8
#     esi = esi ^ ecx
#     sil ^= stored[i]
#     => keyB = (esi & 0xFF) after all transforms, XOR'd with stored[i]
#
#   Keystream A (from eax):
#     edx = eax_i ^ r15d
#     cl = r9d_i & 7
#     edx = ROL32(edx, cl)
#     ecx = edx >> 15
#     ecx = ecx ^ edx
#     edx = ecx >> 7
#     edx = edx ^ ecx
#     dl ^= input[i]
#     => keyA = (edx & 0xFF) after transforms, XOR'd with input[i]
#
#   Check: dl == sil  =>  keyA ^ input[i] == keyB ^ stored[i]
#   => input[i] ^ keyA_byte == stored[i] ^ keyB_byte
#   => input[i] = keyA_byte ^ keyB_byte ^ stored[i]
#   Wait, let me re-read...
#
#   Actually: dl = keyA ^ input[i], sil = keyB ^ stored[i]
#   Check: dl == sil => keyA ^ input[i] == keyB ^ stored[i]
#   => input[i] = keyA ^ keyB ^ stored[i]
#   Hmm, but that's not right either. Let me re-trace.

def rol32(val, n):
    n = n % 32
    val = val & 0xFFFFFFFF
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

flag_chars = []
eax = 0xa97288ed
ebx = 0x9e3779b9
r9d = 0

for i in range(r12):
    # Compute keyB
    esi = ebx ^ 0xc19ef49e
    esi = esi & 0xFFFFFFFF
    cl = i & 7
    esi = rol32(esi, cl)
    ecx = (esi >> 16) & 0xFFFFFFFF
    ecx = ecx ^ esi
    ecx = ecx & 0xFFFFFFFF
    esi = (ecx >> 8) & 0xFFFFFFFF
    esi = esi ^ ecx
    esi = esi & 0xFFFFFFFF
    keyB = (esi & 0xFF) ^ stored[i]

    # Compute keyA (without input XOR)
    edx = eax ^ r15
    edx = edx & 0xFFFFFFFF
    cl2 = r9d & 7
    edx = rol32(edx, cl2)
    ecx2 = (edx >> 15) & 0xFFFFFFFF
    ecx2 = ecx2 ^ edx
    ecx2 = ecx2 & 0xFFFFFFFF
    edx2 = (ecx2 >> 7) & 0xFFFFFFFF
    edx2 = edx2 ^ ecx2
    edx2 = edx2 & 0xFFFFFFFF
    keyA = edx2 & 0xFF

    # dl = keyA ^ input[i], sil = keyB
    # Check: dl == sil => keyA ^ input[i] == keyB
    # => input[i] = keyA ^ keyB
    input_byte = keyA ^ keyB
    flag_chars.append(input_byte)

    # Update loop variables
    eax = (eax + 0x85ebca6b) & 0xFFFFFFFF
    ebx = (ebx + 0x9e3779b9) & 0xFFFFFFFF
    r9d = (r9d + 3) & 0xFFFFFFFF

flag = bytes(flag_chars)
print(f"\nRecovered input: {flag}")
print(f"Flag: ENO{{{flag.decode()}}}")
