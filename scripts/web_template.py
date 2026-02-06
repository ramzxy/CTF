#!/usr/bin/env python3
"""CTF Web Exploit Template"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080'
s = requests.Session()


def exploit():
    # === EXPLOIT HERE ===

    r = s.get(f'{TARGET}/')
    print(r.status_code, r.text[:500])

    # Print flag
    # print(f"FLAG: {flag}")


if __name__ == '__main__':
    exploit()
