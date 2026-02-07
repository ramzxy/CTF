#!/usr/bin/env python3
import sys

try:
    with open('dinos.bin', 'rb') as f:
        data = f.read(100) # Check header

    print(f"Read {len(data)} bytes")
    
    # Try all single byte XOR keys
    common_headers = {
        b'\x89PNG': 'PNG',
        b'\xFF\xD8\xFF': 'JPG',
        b'GIF8': 'GIF',
        b'%PDF': 'PDF',
        b'PK\x03\x04': 'ZIP',
        b'ENO': 'Text starts with ENO'
    }
    
    for key in range(256):
        xored = bytes([b ^ key for b in data[:10]])
        
        # Check against common headers
        for magic, name in common_headers.items():
            if xored.startswith(magic):
                print(f"FOUND MATCH with key {key} (0x{key:02X}): {name}")
                print(f"Header: {xored.hex()}")
                
        # Heuristic: looking for readable text
        try:
            text = xored.decode('utf-8')
            if text.isprintable():
                # print(f"Key {key}: {text}")
                pass
        except:
            pass

except Exception as e:
    print(f"Error: {e}")
