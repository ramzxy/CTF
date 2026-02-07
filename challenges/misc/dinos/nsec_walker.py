#!/usr/bin/env python3
import subprocess
import time

SERVER = "52.59.124.14"
PORT = "5052"
START_DOMAIN = "dinos.nullcon.net"

current = START_DOMAIN
visited = set([current])
chain = []

print(f"Walking from {current}...")

for i in range(200):
    cmd = ["dig", f"@{SERVER}", "-p", PORT, "+short", "NSEC", current]
    try:
        output = subprocess.check_output(cmd, timeout=5).decode('utf-8').strip()
    except Exception as e:
        print(f"Error at {current}: {e}")
        break
        
    if not output:
        print(f"No NSEC for {current}")
        break
        
    # Output format: next_domain. types...
    parts = output.split()
    next_domain = parts[0].rstrip('.')
    
    # Check if wrapped
    if next_domain == START_DOMAIN:
        print("Wrapped around to start!")
        break
        
    if next_domain in visited:
        print(f"Loop at {next_domain}")
        break
        
    print(f"{i}: {next_domain}")
    
    # Check TXT record for this domain too
    try:
        txt_cmd = ["dig", f"@{SERVER}", "-p", PORT, "+short", "TXT", next_domain]
        txt = subprocess.check_output(txt_cmd, timeout=2).decode('utf-8').strip()
        if txt:
            print(f"  TXT: {txt}")
    except:
        pass

    chain.append(next_domain)
    visited.add(next_domain)
    current = next_domain
    
print(f"Found {len(chain)} domains")
