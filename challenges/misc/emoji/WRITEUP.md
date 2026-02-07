# Emoji - Writeup

**Points:** 209  
**Solves:** 98

## Challenge Analysis

The challenge provided a ZIP file `files/chall.zip` containing a `README.md` file with a single emoji followed by many invisible characters.

## Solution

Hex-dumping the `README.md` file reveals hidden Unicode characters following the first emoji.
Analysis showed these are Unicode variation selectors in the range U+E0100 - U+E01FF.

Specifically, the characters were offset from ASCII by `0xE0100` minus `0x10`. So to decode:
`decoded_char = chr(ord(encoded_char) - 0xE0100 + 0x10)`

## Exploit

We wrote a Python script to iterate through the characters in the `README.md` file:

1. Filter for characters in range `0xE0100` to `0xE01FF`.
2. Subtract the base and add offset to get ASCII.
3. Construct the flag.

**Flag:** `ENO{EM0J1S_UN1COD3_1S_MAG1C}`
