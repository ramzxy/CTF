import socket
import sys
import time
import subprocess
import os

# Context
HOST = '52.59.124.14'
PORT = 5104

def long_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def bytes_to_long(b):
    return int.from_bytes(b, 'big')

class Remote:
    def __init__(self, host, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(5.0)
        self.s.connect((host, port))
        self.buf = b''

    def recvline(self):
        while b'\n' not in self.buf:
            data = self.s.recv(1024)
            if not data:
                break
            self.buf += data
        if b'\n' in self.buf:
            line, self.buf = self.buf.split(b'\n', 1)
            return line
        return b''

    def recvuntil(self, marker):
        while marker not in self.buf:
            data = self.s.recv(1024)
            if not data:
                break
            self.buf += data
        if marker in self.buf:
            pre, self.buf = self.buf.split(marker, 1)
            return pre + marker
        return b''

    def sendline(self, data):
        self.s.sendall(data + b'\n')

    def close(self):
        self.s.close()

def solve():
    r = Remote(HOST, PORT)

    # 1. Receive N
    line = r.recvline()
    try:
        N = int(line.strip())
        print(f"[+] Received N: {N}")
    except ValueError:
        print(f"[-] Failed to parse N. Line was: {line}")
        return

    # 2. Receive Ciphertext
    line = r.recvline()
    cipher_hex = line.strip().decode()
    cipher_bytes = bytes.fromhex(cipher_hex)
    print(f"[+] Received Ciphertext ({len(cipher_bytes)} bytes)")

    # 3. Parse Ciphertext
    msg_len = bytes_to_long(cipher_bytes[:4])
    iv = cipher_bytes[4:20]
    enc_msg = cipher_bytes[20:20+msg_len]
    enc_key_bytes = cipher_bytes[20+msg_len:]
    enc_key = bytes_to_long(enc_key_bytes)

    print(f"[+] Message Length: {msg_len}")
    print(f"[+] IV: {iv.hex()}")
    print(f"[+] Encrypted Key (int): {enc_key}")

    e = 65537
    LIMIT = 1 << 128

    def oracle(multiplier):
        new_enc_key_int = (enc_key * pow(multiplier, e, N)) % N
        new_enc_key_bytes = long_to_bytes(new_enc_key_int)
        
        new_cipher = cipher_bytes[:20+msg_len] + new_enc_key_bytes
        
        # Consume "input cipher (hex): " prompt
        r.recvuntil(b'input cipher (hex): ')
        r.sendline(new_cipher.hex().encode())
        
        resp = r.recvline().decode().strip()
        
        if 'something else went wrong' in resp:
            return True # key > LIMIT
        elif 'invalid padding' in resp:
            return False # key <= LIMIT
        elif "That's the right start" in resp:
             print("Hit the jackpot early?")
             return False
        else:
            return False

    # 5. Binary Search
    L = 1 << 64
    R = 1 << 128 # Safe upper bound

    print(f"[*] Starting Binary Search in range [{L}, {R}]")
    
    print("Checking bounds...")
    if not oracle(R):
         print("Oracle(R) is False. Increasing R.")
         R = R * 2
         while not oracle(R):
             R = R * 2
             print(f"New R: {R}")
             
    print(f"Bounds verified. L={L}, R={R}")
    
    count = 0
    while L < R:
        mid = (L + R) // 2
        if oracle(mid):
            R = mid
        else:
            L = mid + 1
        count += 1
        if count % 10 == 0:
            print(f"Step {count}: L={L}")
            
    s_found = L
    print(f"[+] Found s: {s_found}")
    
    key_int = LIMIT // s_found
    print(f"[+] Calculated Key: {key_int}")
    
    key_bytes = long_to_bytes(key_int).rjust(16, b'\x00')
    print(f"[+] Constructing Key: {key_bytes.hex()}")

    # Decrypt using openssl
    with open('iv.bin', 'wb') as f:
        f.write(iv)
    with open('ciphertext.bin', 'wb') as f:
        f.write(enc_msg)
        
    print("[*] Running openssl decryption (trying candidates)...")
    
    # Try range of keys
    for offset in range(-2, 3):
        k_val = key_int + offset
        candidate_key = long_to_bytes(k_val).rjust(16, b'\x00')
        print(f"Trying key: {candidate_key.hex()}")
        
        cmd = [
            'openssl', 'enc', '-d', '-aes-128-cbc',
            '-K', candidate_key.hex(),
            '-iv', iv.hex(),
            '-in', 'ciphertext.bin',
            '-nopad' # Disable padding check to see raw output
        ]
        try:
            res = subprocess.run(cmd, capture_output=True)
            pt = res.stdout
            if b'ENO' in pt:
                print(f"\n[SUCCESS] Flag found with offset {offset}!")
                print(f"Plaintext (hex): {pt.hex()}")
                print(f"Plaintext (raw): {pt}")
                try:
                    print(f"Flag: {pt.decode().strip()}")
                except:
                    pass
                break
        except Exception as e:
            print(f"[-] Error: {e}")


    r.close()

if __name__ == "__main__":
    solve()
