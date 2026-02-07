#!/usr/bin/env python3
import sys
from PIL import Image
import os

def analyze(filename):
    try:
        img = Image.open(filename).convert('L')
        width, height = img.size
        pixels = list(img.getdata())
        
        # Calculate row variance manually
        row_variances = []
        for y in range(height):
            row = pixels[y*width : (y+1)*width]
            if not row: continue
            mean = sum(row) / len(row)
            variance = sum((x - mean) ** 2 for x in row) / len(row)
            row_variances.append(variance)
            
        if not row_variances: return 0
        score = sum(row_variances) / len(row_variances)
        print(f"{filename}: score {score:.2f}")
        return score
    except Exception as e:
        print(f"Error {filename}: {e}")
        return 0

files = [f for f in os.listdir('.') if f.startswith('dinos_rgb_') and f.endswith('.png')]
scores = []
for f in files:
    s = analyze(f)
    scores.append((s, f))

scores.sort(reverse=True)
print("\nTop candidates:")
for s, f in scores[:3]:
    print(f"{f}: {s:.2f}")
