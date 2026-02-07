import socket
import sys
import time
import base64
import random

# Use standard lists since numpy might not be available either,
# but the original challenge used numpy, so it's likely available?
# The challenge file imported numpy. So numpy should be there.
# If not, I'll need to rewrite matrix logic too.
# Let's assume numpy IS available since the challenge uses it.
# If not, I will see an error.
try:
    import numpy as np
except ImportError:
    print("Error: numpy is required but not installed.")
    sys.exit(1)

# Configuration
HOST = '52.59.124.14'
PORT = 5101
ALPHABET = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
MOD = len(ALPHABET) # 65
N = 16

def get_char_idx(char):
    if isinstance(char, int):
        return char # It's already an index if we iterating over bytes
    return ALPHABET.index(char)

def get_idx_char(idx):
    return ALPHABET[idx]

def parse_response(line):
    # expect format: [num, num, ..., num]
    line = line.strip()
    if line.startswith(b'[') and line.endswith(b']'):
        try:
            # Safer eval
            content = line[1:-1]
            return [int(x.strip()) for x in content.split(b',')]
        except:
            return None
    return None

# Modular Inverse
def mod_inv(a, m):
    return pow(int(a), -1, int(m))

# Matrix Inverse Modulo m
def mat_inv_mod(A, m):
    # Gaussian elimination over GF(m)
    # A is numpy array
    n = A.shape[0]
    A = np.hstack([A, np.eye(n, dtype=int)])
    
    for i in range(n):
        # Find pivot
        pivot_val = A[i, i] % m
        if pivot_val == 0:
            # Need to swap rows?
            for k in range(i+1, n):
                if A[k, i] % m != 0:
                    A[[i, k]] = A[[k, i]]
                    pivot_val = A[i, i] % m
                    break
        
        pivot = pow(int(pivot_val), -1, m)
        A[i] = (A[i] * pivot) % m
        
        for j in range(n):
            if i != j:
                factor = A[j, i]
                A[j] = (A[j] - factor * A[i]) % m
                
    return A[:, n:]

def solve_affine(X, Y, m):
    # Y_diff = A * X_diff
    # A = Y_diff * inv(X_diff)
    
    # We have many pairs. We need to find N+1 pairs (including base x0) such that
    # the N difference vectors are linearly independent mod m.
    
    num_pairs = len(X)
    if num_pairs < N + 1:
        return None, None
    
    # Try 100 times to find a good subset
    for attempt in range(100):
        # Pick 1 random base index
        # indices = list(range(num_pairs))
        # random.shuffle(indices)
        # selection = indices[:N+1]
        
        # Actually, let's just pick N+1 random indices
        indices = random.sample(range(num_pairs), N + 1)
        
        X_subset = X[indices]
        Y_subset = Y[indices]
        
        x0 = X_subset[0]
        y0 = Y_subset[0]
        
        X_diff = []
        Y_diff = []
        
        for i in range(1, len(X_subset)):
            X_diff.append((X_subset[i] - x0) % m)
            Y_diff.append((Y_subset[i] - y0) % m)
            
        X_diff_mat = np.array(X_diff).T # 16x16
        Y_diff_mat = np.array(Y_diff).T # 16x16
        
        try:
            X_diff_inv = mat_inv_mod(X_diff_mat, m)
            # Check if it actually inverted (sometimes mat_inv_mod might return something even if singular if not carefully checked, 
            # though my implementation checks pivots)
            
            # Since mat_inv_mod raises if singular?
            # My implementation: if pivot is 0, it loops. if all 0, it leaves 0.
            # But pow(0, -1, m) raises ValueError.
            # So it will crash if singular.
            
            A = (Y_diff_mat @ X_diff_inv) % m
            b = (y0 - A @ x0) % m
            return A, b
        except ValueError:
            # Singular matrix
            continue
        except Exception as e:
            continue

    return None, None

def crt(a1, m1, a2, m2):
    k = ((a2 - a1) * pow(m1, -1, m2)) % m2
    return (a1 + m1 * k) % (m1 * m2)

class NetCat:
    def __init__(self, ip, port):
        self.buff = b''
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((ip, port))

    def read(self, length=1024):
        return self.socket.recv(length)

    def read_until(self, data):
        while data not in self.buff:
            self.buff += self.socket.recv(1024)
        pos = self.buff.find(data)
        rval = self.buff[:pos + len(data)]
        self.buff = self.buff[pos + len(data):]
        return rval
    
    def read_line(self):
        return self.read_until(b'\n')

    def write(self, data):
        self.socket.sendall(data)

    def close(self):
        self.socket.close()

def run_attack():
    try:
        print(f"Connecting to {HOST}:{PORT}...")
        nc = NetCat(HOST, PORT)
        
        # Read until we get the list
        # The server sends: [ ... ]
        
        line = nc.read_line()
        while not line.strip().startswith(b'['):
            line = nc.read_line()
            if not line: break
        
        encrypted_flag_blocks = parse_response(line)
        print(f"Encrypted flag length: {len(encrypted_flag_blocks)}")
        
        enc_flag_array = np.array(encrypted_flag_blocks, dtype=int)
        num_blocks = len(enc_flag_array) // N
        
        inputs = []
        outputs = []
        
        target_pairs = N + 5 # Buffer
        
        print("Collecting pairs...")
        
        # Wait for the prompt "enter your message (in hex): "
        nc.read_until(b'(in hex): ')
        
        while len(inputs) < target_pairs:
            rand_bytes = bytes([random.randint(0, 255) for _ in range(12)])
            
            hex_input = rand_bytes.hex().encode()
            nc.write(hex_input + b'\n')
            
            resp_line = nc.read_line()
            # Parse response
            cipher_nums = parse_response(resp_line)
            
            # Read next prompt
            nc.read_until(b'(in hex): ')
            
            if not cipher_nums:
                continue
                
            y_vec = np.array(cipher_nums[:N], dtype=int)
            
            b64_str = base64.b64encode(rand_bytes)
            x_vec = np.array([ALPHABET.index(c) for c in b64_str], dtype=int)
            
            inputs.append(x_vec)
            outputs.append(y_vec)
            
        nc.close()
        
        X = np.array(inputs)
        Y = np.array(outputs)
        
        print(f"Collected {len(X)} pairs")
        
        A5,  b5  = solve_affine(X, Y, 5)
        A13, b13 = solve_affine(X, Y, 13)
        
        if A5 is None or A13 is None:
            print("Error: Could not solve linear system.")
            return False
            
        A = np.zeros((N, N), dtype=int)
        for i in range(N):
            for j in range(N):
                A[i,j] = crt(A5[i,j], 5, A13[i,j], 13)
                
        b = np.zeros(N, dtype=int)
        for i in range(N):
            b[i] = crt(b5[i], 5, b13[i], 13)
            
        print("Recovered Key A and b")
        
        flag_decrypted_bytes = b''
        
        # Invert A mod 5 and mod 13
        try:
            A5_inv = mat_inv_mod(A5, 5)
            A13_inv = mat_inv_mod(A13, 13)
        except Exception as e:
            print(f"Failed to invert A: {e}. Key might be singular.")
            return False

        A_inv = np.zeros((N, N), dtype=int)
        for i in range(N):
            for j in range(N):
                A_inv[i,j] = crt(A5_inv[i,j], 5, A13_inv[i,j], 13)

        for i in range(num_blocks):
            y_blk = enc_flag_array[i*N : (i+1)*N]
            diff = (y_blk - b) % MOD
            x_blk = (A_inv @ diff) % MOD
            block_chars = b''.join([bytes([get_idx_char(v)]) for v in x_blk])
            flag_decrypted_bytes += block_chars
            
        print(f"Decrypted Base64: {flag_decrypted_bytes}")
        
        try:
            flag = base64.b64decode(flag_decrypted_bytes)
            flag_str = flag.decode(errors='ignore')
            print(f"FLAG: {flag_str}")
            if "CTF{" in flag_str:
                return True
        except Exception as e:
            print(f"Failed to decode base64: {e}")
            print(f"Raw: {flag_decrypted_bytes}")
            
        return False
    except Exception as e:
        print(f"Attempt failed with exception: {e}")
        return False

def main():
    while True:
        if run_attack():
            break
        print("Retrying...")
        time.sleep(1)

if __name__ == '__main__':
    main()

