#!/usr/bin/env python3
import sys
from PIL import Image
import numpy as np
import os

def analyze(filename):
    try:
        img = Image.open(filename).convert('L')
        data = np.array(img)
        # Calculate row variance/entropy to detect text lines
        row_var = np.var(data, axis=1)
        score = np.mean(row_var)
        print(f"{filename}: score {score:.2f}")
        return score
    except:
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
