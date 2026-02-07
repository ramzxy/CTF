#!/usr/bin/env python3
import sys
from PIL import Image

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
                # Threshold
                if val < 128:
                    line += "##"
                else:
                    line += "  "
            print(line)
        print()
    except Exception as e:
        print(f"Error {filename}: {e}")

if len(sys.argv) > 1:
    to_ascii(sys.argv[1])
else:
    to_ascii('dinos_final_45x28.png')
