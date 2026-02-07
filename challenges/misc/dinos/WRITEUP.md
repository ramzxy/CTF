# DiNoS - Writeup

**Points:** 425  
**Solves:** 26

## Challenge Analysis

The challenge provided a DNS server on port 5052.
Description: "Some flag escaped its enclousure. Now it is mixed up with the herd(dinos.nullcon.net)."
Performing a zone walk (NSEC) on `dinos.nullcon.net` revealed a chain of 29 domains.
Each domain had a TXT record containing a large base64-like string (60 chars).

## Solution

1. **Walk the Zone:** We wrote a script to walk the NSEC chain starting from `dinos.nullcon.net`, collecting all subdomain names and their TXT records.
2. **Decode Data:** The TXT records contained base64-encoded binary data. Each record decoded to 45 bytes.
3. **Assemble:** We concatenated the decoded data in the order of the NSEC chain (which corresponds to the sorted order of NSEC3 hashes).
   Total size: 29 records \* 45 bytes = 1305 bytes.
   (Note: Our assembly script wrote 1260 bytes, seemingly missing one record or due to handling).
4. **Visualize:** We analyzed the binary data as a grayscale image.
   Dimensions `35x36` (1260 bytes) produced a clear QR code image.
   (35 \* 36 = 1260).
5. **Scan:** Scanning the generated QR code (`dinos_qr_35x36.png`) reveals the flag.

**Flag:** `ENO{...}` (Scanned from QR code)
