#!/usr/bin/env python3
import sys
from PIL import Image
import os

try:
    with open('dinos.bin', 'rb') as f:
        data = f.read()
    
    length = len(data)
    print(f"Data length: {length} bytes")
    
    # 1260 bytes
    # RGB = 3 bytes/pixel -> 420 pixels
    # Factors of 420: 20x21, 21x20, 15x28, 28x15, 12x35, 35x12, 10x42, 42x10...
    
    dimensions = [
        (20, 21), (21, 20),
        (15, 28), (28, 15),
        (12, 35), (35, 12),
        (10, 42), (42, 10),
        (30, 14), (14, 30),
        (60, 7), (7, 60)
    ]
    
    for w, h in dimensions:
        try:
            img = Image.frombytes('RGB', (w, h), data)
            img.save(f'dinos_rgb_{w}x{h}.png')
            print(f"Saved dinos_rgb_{w}x{h}.png")
        except Exception as e:
            print(f"Error RGB {w}x{h}: {e}")

except Exception as e:
    print(f"Error: {e}")
