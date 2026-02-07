# Meowy

**Category:** web | **Points:** 461 | **Flag:** `ENO{w3rkz3ug_p1n_byp4ss_v1a_c00k13_f0rg3ry_l3ads_2_RCE!}`

## Overview
A Flask cat image gallery with an obfuscated source code, Werkzeug debugger enabled, and an SSRF endpoint.

## Solution
Multi-step chain combining several vulnerabilities:

### 1. Crack Flask Secret Key
The app uses `RandomWords` for the secret key. Cracked with `flask-unsign` and a dictionary wordlist: `pannuscorium`.

### 2. Forge Admin Session
Signed a Flask session cookie with `{'is_admin': True}` to unlock the `/fetch` SSRF endpoint.

### 3. SSRF via pycurl
The `/fetch` endpoint uses pycurl with `FOLLOWLOCATION=True` and supports `file://` and `gopher://` protocols. Read the real (unobfuscated) `app.py` via `file:///proc/self/cwd/app.py`.

### 4. Werkzeug Debugger PIN Calculation
Gathered all inputs for the PIN via file reads:
- `/etc/machine-id`: `c8f5e9d2a1b3c4d5e6f7a8b9c0d1e2f3`
- `/sys/class/net/eth0/address`: `a6:74:18:66:49:57`
- username: `ctfplayer`, modname: `flask.app`, appname: `Flask`
- Computed PIN: `199-669-506`

### 5. PIN Cookie Forgery via Gopher SSRF
The custom `SecureDebuggedApplication` blocks `pinauth` requests, preventing normal PIN entry. Bypass:
1. SSRF to `http://127.0.0.1:5000/console` leaked the debugger `SECRET`
2. Computed the PIN cookie name (`__wzd...`) and value (`timestamp|hash_pin(pin)`)
3. Used `gopher://` protocol to craft a raw HTTP request with the forged cookie header
4. Achieved RCE via the Werkzeug debugger console

### 6. Read Flag
`/flag.txt` was root-owned (0600), but a SUID `/readflag` binary was available. Executed it via the debugger to get the flag.

## Key Takeaways
- pycurl's `gopher://` support enables raw TCP requests with arbitrary headers — perfect for cookie injection in SSRF.
- Werkzeug debugger PIN can be calculated from leaked system files, and the trust cookie can be forged without using `pinauth`.
- Always check for SUID binaries (`/readflag`) when direct file read is blocked.
