#!/usr/bin/env python3
"""CTF Solve Script Template

Usage:
    python solve.py                # Local
    python solve.py REMOTE         # Remote (uses pwntools args)
"""
from pwn import *
import sys

# === CHALLENGE CONFIG ===
BINARY = './challenge'
HOST = 'challenge.ctf.com'
PORT = 1337

# context.binary = elf = ELF(BINARY)
# context.log_level = 'debug'


def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(BINARY)


def exploit(io):
    # === EXPLOIT HERE ===

    io.interactive()


def main():
    io = conn()
    exploit(io)


if __name__ == '__main__':
    main()
