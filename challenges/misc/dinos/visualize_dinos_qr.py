#!/usr/bin/env python3
import sys
from PIL import Image
import os

try:
    with open('dinos.bin', 'rb') as f:
        data = f.read()
    
    # 1260 bytes = 35 * 36
    # Try 35x36 and 36x35
    dims = [(35, 36), (36, 35)]
    
    for w, h in dims:
        try:
            # Grayscale (L) - 1 byte per pixel
            img = Image.frombytes('L', (w, h), data)
            img.save(f'dinos_qr_{w}x{h}.png')
            print(f"Saved dinos_qr_{w}x{h}.png")
            
            # Also scale up for readability
            img_big = img.resize((w*10, h*10), Image.NEAREST)
            img_big.save(f'dinos_qr_{w}x{h}_big.png')
            
        except Exception as e:
            print(f"Error {w}x{h}: {e}")

except Exception as e:
    print(f"Error: {e}")
