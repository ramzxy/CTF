import sys
import zlib
import re

def extract_streams():
    with open('files/Planned-Flags-signed-2.pdf', 'rb') as f:
        data = f.read()

    # Find stream objects
    # This regex is simplistic but might catch raw streams
    # More robust would be to use pypdf or PyMuPDF, but let's try raw first
    stream_blocks = re.findall(b'stream[\r\n]+(.*?)[\r\n]+endstream', data, re.DOTALL)
    
    print(f"Found {len(stream_blocks)} potential stream blocks")
    
    for i, block in enumerate(stream_blocks):
        try:
            # Try to decompress
            content = zlib.decompress(block.strip())
            text = content.decode('latin-1', errors='ignore')
            
            # Look for ENO
            if 'ENO' in text:
                print(f"--- Stream {i} contains 'ENO' ---")
                # Print context around 'ENO'
                matches = re.finditer(r'ENO\{[^}]*\}', text)
                for m in matches:
                    print(f"Found potential flag: {m.group(0)}")
                
                # Also print nearby text just in case
                idx = text.find('ENO')
                start = max(0, idx - 50)
                end = min(len(text), idx + 100)
                print(f"Context: {text[start:end]}")
                print()
                
        except Exception as e:
            # Not zlib compressed or other issue
            pass

if __name__ == '__main__':
    extract_streams()
