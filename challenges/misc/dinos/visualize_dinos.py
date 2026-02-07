#!/usr/bin/env python3
import sys
from PIL import Image

try:
    with open('dinos.bin', 'rb') as f:
        data = f.read()
    
    length = len(data)
    print(f"Data length: {length} bytes")
    
    # Try different widths
    # 29 records * 45 bytes = 1305 bytes
    # RGB = 3 bytes/pixel -> 435 pixels
    # Factors of 435: 1, 3, 5, 15, 29, 87, 145, 435
    
    widths = [15, 29, 87, 145]
    
    for w in widths:
        h = 435 // w
        try:
            img = Image.frombytes('RGB', (w, h), data)
            img.save(f'dinos_rgb_{w}x{h}.png')
            print(f"Saved dinos_rgb_{w}x{h}.png")
        except Exception as e:
            print(f"Error RGB {w}x{h}: {e}")
            
    # Try Grayscale (L) -> 1305 pixels
    # Factors of 1305: 1, 3, 5, 9, 15, 29, 45, 87, 145, 261, 435...
    
    widths_l = [29, 45, 87]
    for w in widths_l:
        h = 1305 // w
        try:
            img = Image.frombytes('L', (w, h), data)
            img.save(f'dinos_gray_{w}x{h}.png')
            print(f"Saved dinos_gray_{w}x{h}.png")
        except Exception as e:
            print(f"Error Gray {w}x{h}: {e}")

except Exception as e:
    print(f"Error: {e}")
