from pwn import *

# S-box from the challenge  
S = (
    0x64, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

S_inv = [0] * 256
for i in range(256):
    S_inv[S[i]] = i

def rotate(l, k):
    k %= len(l)
    return l[k:] + l[:k]

def cross(m, s):
    res = 0
    for i in range(4):
        if m[i] == 1:
            res ^= s[i]
        elif m[i] == 2:
            res ^= (s[i] << 1) ^ (0x1b if s[i] >= 128 else 0)
        else:  # 3
            res ^= s[i] ^ ((s[i] << 1) ^ (0x1b if s[i] >= 128 else 0))
    return res & 0xff

def mix_column(state):
    cols = [[state[i][j] for i in range(4)] for j in range(4)]
    base_m = [2, 3, 1, 1]
    res = [[cross(rotate(base_m, -j), cols[i]) for j in range(4)] for i in range(4)]
    return [[res[i][j] for i in range(4)] for j in range(4)]

def gf_mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return result

INV_MIX = [[0x0e, 0x0b, 0x0d, 0x09], [0x09, 0x0e, 0x0b, 0x0d],
           [0x0d, 0x09, 0x0e, 0x0b], [0x0b, 0x0d, 0x09, 0x0e]]

def inv_mix_column(state):
    cols = [[state[i][j] for i in range(4)] for j in range(4)]
    res = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mul(INV_MIX[j][k], cols[i][k])
            res[i][j] = val
    return [[res[i][j] for i in range(4)] for j in range(4)]

def bytes_to_state(b):
    return [[b[i*4+j] for j in range(4)] for i in range(4)]

def state_to_bytes(state):
    return bytes([state[i][j] for i in range(4) for j in range(4)])

def sb_sr_mc(state):
    """Apply SubBytes, ShiftRows, MixColumns"""
    state = [[S[c] for c in row] for row in state]
    state = [rotate(state[i], i) for i in range(4)]
    state = mix_column(state)
    return state

def inv_sb_sr_mc(state):
    """Apply inverse MixColumns, ShiftRows, SubBytes"""
    state = inv_mix_column(state)
    state = [rotate(state[i], -i) for i in range(4)]
    state = [[S_inv[c] for c in row] for row in state]
    return state


def solve():
    r = remote('52.59.124.14', 5103)
    
    r.recvuntil(b"cipher.hex() = '")
    key_cipher = bytes.fromhex(r.recvuntil(b"'", drop=True).decode())
    print(f"[+] E(k,k) = {key_cipher.hex()}")
    
    def oracle(msg: bytes):
        r.recvuntil(b'message to encrypt: ')
        r.sendline(msg.hex().encode())
        r.recvuntil(b"cipher.hex() = '")
        return bytes.fromhex(r.recvuntil(b"'", drop=True).decode())
    
    # CIPHER ANALYSIS:
    # Initial state (when M=K): [[42,0,0,0], [0,0,0,0], ...]
    # 
    # Round r: SB -> SR -> MC -> ARK(rotate(K, r+1), r+1)
    # 
    # Let's trace through:
    # s0 = init = [[42,0,0,...], ...]  (KNOWN)
    # t0 = SB_SR_MC(s0)                (KNOWN - no key involved!)
    # s1 = t0 XOR rotate(K,1) XOR [43 at [0][0]]
    # t1 = SB_SR_MC(s1)                (depends on K due to s1)
    # s2 = t1 XOR rotate(K,2) XOR [40 at [0][0]]
    # ...
    # s16 = t15 XOR rotate(K,16) XOR [58 at [0][0]] = ciphertext
    #
    # Since rotate(K,16) = K, we have:
    # ciphertext = t15 XOR K XOR [58,0,0,...]
    # So: K = ciphertext XOR t15 XOR [58,0,0,...]
    #
    # But t15 = SB_SR_MC(s15), and s15 depends on K...
    # This creates a recursive dependency.
    #
    # ORACLE ATTACK:
    # We want to find M such that E_K(M) = ciphertext.
    # By construction, M = K is the only such value (assuming the cipher is a PRP).
    #
    # DIFFERENTIAL ATTACK using oracle:
    # E_K(0) starts from: 0 XOR K = K, then [0][0] ^= 42, giving K with K[0]^=42
    # E_K(K) starts from: K XOR K = 0, then [0][0] ^= 42, giving [42,0,...]
    #
    # The DIFFERENCE of initial states = (K with K[0]^42) XOR [42,0,...] = K XOR [K[0]^42^42,...] = K!
    #
    # After SB: S(a) XOR S(b) for each byte - this is nonlinear but predictable!
    
    c0 = oracle(bytes(16))
    print(f"[+] E(0) = {c0.hex()}")
    
    # E(0) encrypts message 0 with key K:
    # - Initial: 0 XOR K = K
    # - After ARK(0): K, then [0][0] ^= 42
    # So initial state = K with K[0] ^= 42
    # 
    # E(K) encrypts message K with key K:
    # - Initial: K XOR K = 0
    # - After ARK(0): [42, 0, 0, ...]
    #
    # The difference in initial states is:
    # (K with K[0]^42) XOR (42, 0, ...) = (K[0]^42^42, K[1], ...) = K
    
    # So if we could express E(0) XOR E(K) in terms of the initial state difference K,
    # we could solve for K!
    
    # Let D = E(0) XOR E(K) = c0 XOR key_cipher
    D = bytes(a ^ b for a, b in zip(c0, key_cipher))
    print(f"[+] D = E(0) XOR E(K) = {D.hex()}")
    
    # D is the differential of the encryption with input difference K.
    # For AES-like ciphers, certain input differences lead to predictable output differences.
    # But this depends heavily on the key and the specific differential characteristic.
    
    # SLIDE ATTACK insight:
    # The key schedule is just rotations: K1=rot(K,1), K2=rot(K,2), ..., K16=rot(K,16)=K
    # 
    # If we encrypt M with key K, and encrypt rot(M,1) with key rot(K,1),
    # the two encryptions might have related structures...
    #
    # Actually, let's try a RELATED-KEY attack concept:
    # E_K(M) vs E_{rot(K,1)}(?)
    # But we can only encrypt with key K, not its rotations.
    
    # Let me try encrypting rotated versions of E(0):
    print("[*] Trying rotated encryptions...")
    
    for rot in range(1, 16):
        # Encrypt rot(c0, rot)
        rotated = bytes(rotate(list(c0), rot))
        ct = oracle(rotated)
        
        # Check if this gives us key_cipher or something related
        if ct == key_cipher:
            print(f"[+] E(rot(E(0), {rot})) = key_cipher! -> K = rot(E(0), {rot})")
            key = rotated
            r.recvuntil(b'message to encrypt: ')
            r.sendline(b'end')
            r.recvuntil(b'Can you tell me the key in hex? ')
            r.sendline(key.hex().encode())
            print(r.recvall().decode())
            return
    
    # Try XOR combinations
    print("[*] Trying XOR combinations...")
    for offset in [42, 43, 58]:
        candidate = bytes([c0[0] ^ offset] + list(c0[1:]))
        if oracle(candidate) == key_cipher:
            print(f"[+] KEY = E(0) with [0]^{offset} = {candidate.hex()}")
            r.recvuntil(b'message to encrypt: ')
            r.sendline(b'end')
            r.recvuntil(b'Can you tell me the key in hex? ')
            r.sendline(candidate.hex().encode())
            print(r.recvall().decode())
            return
    
    # Try using the differential D as the key
    if oracle(D) == key_cipher:
        print(f"[+] KEY = D = {D.hex()}")
        r.recvuntil(b'message to encrypt: ')
        r.sendline(b'end')
        r.recvuntil(b'Can you tell me the key in hex? ')
        r.sendline(D.hex().encode())
        print(r.recvall().decode())
        return
    
    # Try S-box related transforms of D
    transforms = [
        ("S(D)", bytes(S[d] for d in D)),
        ("S_inv(D)", bytes(S_inv[d] for d in D)),
        ("S(c0)", bytes(S[c] for c in c0)),
        ("S_inv(c0)", bytes(S_inv[c] for c in c0)),
        ("S(ct)", bytes(S[c] for c in key_cipher)),
        ("S_inv(ct)", bytes(S_inv[c] for c in key_cipher)),
    ]
    
    for name, candidate in transforms:
        if oracle(candidate) == key_cipher:
            print(f"[+] KEY via {name} = {candidate.hex()}")
            r.recvuntil(b'message to encrypt: ')
            r.sendline(b'end')
            r.recvuntil(b'Can you tell me the key in hex? ')
            r.sendline(candidate.hex().encode())
            print(r.recvall().decode())
            return
    
    print("[!] Clever attacks didn't work")
    print(f"[*] Final data for analysis:")
    print(f"    key_cipher = {key_cipher.hex()}")
    print(f"    c0 = {c0.hex()}")
    print(f"    D = {D.hex()}")
    
    r.recvuntil(b'message to encrypt: ')
    r.sendline(b'end')
    r.close()

if __name__ == '__main__':
    solve()
