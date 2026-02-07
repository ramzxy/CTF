#!/usr/bin/env python3
"""
Pasty CTF Challenge Solver

The vulnerability in compute_sig():
- $h = sha256($id) - 32 bytes
- $m = sha256($key)[0:24] - 24 bytes (key-derived, same for all)
- For each round i (0-3):
    - $b = $h[i*8 : (i+1)*8]
    - $p = ($h[i*8] % 3) * 8  -- selects one of 3 chunks from $m
    - $c = $m[$p : $p+8]
    - Round 0: $o[0:8] = $b ^ $c
    - Round i>0: $o[i*8:] = $b ^ $c ^ $o[(i-1)*8:i*8]

Key insight: We can collect signatures and XOR relationships to recover the 3 key chunks.
Then we can forge a signature for any id (like "flag").
"""

import hashlib
import requests
from bs4 import BeautifulSoup
import re

BASE_URL = "http://52.59.124.14:5005"

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def compute_sig(data: bytes, m: bytes) -> bytes:
    """Compute signature given the data and 24-byte key material m"""
    h = hashlib.sha256(data).digest()
    o = b''
    for i in range(4):
        s = i * 8
        b = h[s:s+8]
        p = (h[s] % 3) * 8
        c = m[p:p+8]
        if i == 0:
            o += xor_bytes(b, c)
        else:
            o += xor_bytes(xor_bytes(b, c), o[s-8:s])
    return o

def get_chunk_index(h: bytes, round_num: int) -> int:
    """Get which key chunk (0, 1, or 2) is used for a given round"""
    return h[round_num * 8] % 3

def create_paste(content: str) -> tuple[str, bytes]:
    """Create a paste and return (id, signature)"""
    session = requests.Session()
    resp = session.post(f"{BASE_URL}/create.php", data={"content": content})
    
    # Parse the redirect URL from the response or find the paste URL
    # The response redirects to index.php with a success message containing the URL
    soup = BeautifulSoup(resp.text, 'html.parser')
    
    # Find the paste URL input
    paste_url_input = soup.find('input', {'id': 'paste-url'})
    if paste_url_input:
        url = paste_url_input.get('value', '')
    else:
        # Try to find URL in the page text
        url_match = re.search(r'view\.php\?id=([a-f0-9]+)&sig=([a-f0-9]+)', resp.text)
        if url_match:
            paste_id = url_match.group(1)
            sig = url_match.group(2)
            return paste_id, bytes.fromhex(sig)
        raise Exception(f"Could not find paste URL in response: {resp.text[:500]}")
    
    # Parse id and sig from URL
    match = re.search(r'id=([a-f0-9]+)&sig=([a-f0-9]+)', url)
    if match:
        paste_id = match.group(1)
        sig = match.group(2)
        return paste_id, bytes.fromhex(sig)
    
    raise Exception(f"Could not parse paste URL: {url}")

def recover_key_chunks():
    """
    Recover the three 8-byte key chunks by creating pastes and analyzing signatures.
    
    For round 0: o[0:8] = h[0:8] ^ m[chunk_idx*8 : chunk_idx*8+8]
    So: m_chunk = h[0:8] ^ o[0:8]
    
    We need to find pastes where round 0 uses each of the 3 chunks.
    """
    chunks = [None, None, None]  # m[0:8], m[8:16], m[16:24]
    
    attempt = 0
    while None in chunks:
        attempt += 1
        paste_id, sig = create_paste(f"recovery_{attempt}_{attempt*7}")
        
        h = hashlib.sha256(paste_id.encode()).digest()
        chunk_idx = get_chunk_index(h, 0)  # Which chunk used in round 0
        
        if chunks[chunk_idx] is None:
            # o[0:8] = h[0:8] ^ m_chunk
            # m_chunk = h[0:8] ^ o[0:8]
            o_first = sig[0:8]
            h_first = h[0:8]
            chunks[chunk_idx] = xor_bytes(h_first, o_first)
            print(f"[+] Recovered chunk {chunk_idx}: {chunks[chunk_idx].hex()}")
        
        if attempt > 50:
            raise Exception("Too many attempts to recover all chunks")
    
    m = chunks[0] + chunks[1] + chunks[2]
    return m

def verify_key_material(m: bytes, paste_id: str, expected_sig: bytes) -> bool:
    """Verify that our recovered key material produces the correct signature"""
    computed = compute_sig(paste_id.encode(), m)
    return computed == expected_sig

def forge_signature(target_id: str, m: bytes) -> bytes:
    """Forge a signature for the target paste id"""
    return compute_sig(target_id.encode(), m)

def get_flag(paste_id: str, sig: bytes) -> str:
    """Retrieve the flag paste"""
    url = f"{BASE_URL}/view.php?id={paste_id}&sig={sig.hex()}"
    print(f"[+] Requesting: {url}")
    resp = requests.get(url)
    return resp.text

def main():
    print("[*] Pasty CTF Solver")
    print("[*] Recovering key material from created pastes...")
    
    # Recover the 24-byte key material
    m = recover_key_chunks()
    print(f"[+] Full key material: {m.hex()}")
    
    # Create a test paste to verify
    print("\n[*] Verifying key material with a test paste...")
    test_id, test_sig = create_paste("verification_test")
    if verify_key_material(m, test_id, test_sig):
        print("[+] Key material verified successfully!")
    else:
        print("[-] Key material verification failed!")
        computed = compute_sig(test_id.encode(), m)
        print(f"    Expected: {test_sig.hex()}")
        print(f"    Computed: {computed.hex()}")
        return
    
    # Forge signature for 'flag' paste
    print("\n[*] Forging signature for 'flag' paste...")
    target = "flag"
    forged_sig = forge_signature(target, m)
    print(f"[+] Forged signature: {forged_sig.hex()}")
    
    # Retrieve the flag
    print("\n[*] Retrieving flag...")
    result = get_flag(target, forged_sig)
    print("\n" + "="*60)
    print("RESULT:")
    print("="*60)
    print(result)

if __name__ == "__main__":
    main()
