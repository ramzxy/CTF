#!/usr/bin/env python3
import sys
from PIL import Image

chars = " .:-=+*#%@"

def to_ascii(filename):
    try:
        img = Image.open(filename).convert('L')
        width, height = img.size
        pixels = list(img.getdata())
        
        print(f"--- {filename} ---")
        for y in range(height):
            line = ""
            for x in range(width):
                val = pixels[y*width + x]
                # Map 0-255 to chars
                idx = int((val / 256) * len(chars))
                line += chars[idx]
            print(line)
        print()
    except Exception as e:
        print(f"Error {filename}: {e}")

if len(sys.argv) > 1:
    to_ascii(sys.argv[1])
else:
    # Try top candidates
    candidates = ['dinos_rgb_42x10.png', 'dinos_rgb_35x12.png', 'dinos_rgb_28x15.png']
    for c in candidates:
        to_ascii(c)
