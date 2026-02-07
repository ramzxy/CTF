#!/usr/bin/env python3
import sys
from PIL import Image
import os
import json

try:
    with open('dinos_dump.json', 'r') as f:
        data = json.load(f)
    print(f"Loaded {len(data)} records")
    
    # Check lengths
    lengths = set()
    for k, v in data.items():
        if v:
            # Base64 decoded length
            import base64
            l = len(base64.b64decode(v))
            lengths.add(l)
    print(f"Record lengths: {lengths}")
    
    with open('dinos.bin', 'rb') as f:
        data = f.read()
    
    length = len(data)
    print(f"Binary length: {length} bytes")
    
    # Try 45 width (row per record)
    w = 45
    h = length // w
    print(f"Trying {w}x{h}")
    
    try:
        img = Image.frombytes('L', (w, h), data)
        img.save(f'dinos_final_{w}x{h}.png')
        print(f"Saved dinos_final_{w}x{h}.png")
        
        # Scale up
        img_big = img.resize((w*10, h*10), Image.NEAREST)
        img_big.save(f'dinos_final_{w}x{h}_big.png')
        
    except Exception as e:
         print(f"Error: {e}")

except Exception as e:
    print(f"Error: {e}")
