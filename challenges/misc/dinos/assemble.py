#!/usr/bin/env python3
import json
import base64
import sys

try:
    with open('dinos_dump.json', 'r') as f:
        data = json.load(f)

    # Sort keys alphabetically as they are hashes/ordered
    sorted_keys = sorted(data.keys())
    
    content = b''
    for k in sorted_keys:
        val = data[k]
        if not val: continue
        try:
            # val is base64
            chunk = base64.b64decode(val)
            content += chunk
            print(f"Added {len(chunk)} bytes from {k[:10]}...")
        except Exception as e:
            print(f"Error decoding {k}: {e}")

    with open('dinos.bin', 'wb') as f:
        f.write(content)

    print(f'Wrote {len(content)} bytes to dinos.bin')
    
except Exception as e:
    print(f"Error: {e}")
