import hashlib
import sys

def solve():
    print("Searching for hash starting with \\xE9 and 5th byte \\x01...", file=sys.stderr)
    
    i = 0
    while True:
        s = str(i).encode()
        md5 = hashlib.md5(s).digest()
        
        # Check first byte is 0xE9 (JMP)
        # Check 5th byte (high byte of rel32) is 0x01
        # This makes rel32 approx 0x01xxxxxx
        # Target = PC (0x40000000) + 5 + rel32 -> 0x41xxxxxx
        # Which lands in the NOP sled.
        if md5[0] == 0xE9 and md5[4] == 0x01:
            print(f"Found input: {s.decode()}")
            print(f"Hash: {md5.hex()}")
            return
        
        i += 1
        if i % 1000000 == 0:
            print(f"Checked {i} hashes...", end='\r', file=sys.stderr)

if __name__ == "__main__":
    solve()
