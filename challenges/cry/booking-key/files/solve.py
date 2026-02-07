from pwn import *
import ast
import string

def decrypt(cipher, book, start):
    """
    Given the cipher (list of offsets), the book, and a starting position,
    decrypt by moving forward by each offset and reading the character.
    """
    current = start
    plaintext = []
    for count in cipher:
        current = (current + count) % len(book)
        plaintext.append(book[current])
    return ''.join(plaintext)


def solve_for_key(cipher, book, charset):
    """
    Brute force all possible starting positions (0 to len(book)-1).
    For each, decode and check if all characters are valid letters.
    """
    valid_solutions = []
    for start in range(len(book)):
        plaintext = decrypt(cipher, book, start)
        if all(c in charset for c in plaintext):
            valid_solutions.append((start, plaintext))
    
    return valid_solutions


def try_solution(r, password):
    """Try a password and return True if correct."""
    r.recvuntil(b'password: ')
    r.sendline(password.encode())
    result = r.recvline().decode().strip()
    return result == 'correct'


# Load the book
BOOK = open('book.txt', 'r').read()
charset = set(c for c in string.ascii_letters if c in BOOK)

# Connect to the server
HOST = '52.59.124.14'
PORT = 5102

for attempt in range(100):  # Try multiple connection attempts
    try:
        r = remote(HOST, PORT)
        
        # Read the "Three times is the charm." intro message
        print(r.recvline().decode())
        
        success = True
        for round_num in range(3):
            # Receive the cipher (list of offsets)
            cipher_line = r.recvline().decode().strip()
            print(f"Round {round_num + 1} cipher: {cipher_line[:80]}...")
            
            # Parse the cipher list
            cipher = ast.literal_eval(cipher_line)
            
            # Find valid solutions
            solutions = solve_for_key(cipher, BOOK, charset)
            print(f"Found {len(solutions)} valid solutions")
            
            if len(solutions) == 0:
                print("ERROR: No valid solutions found!")
                success = False
                break
            elif len(solutions) == 1:
                password = solutions[0][1]
                print(f"Unique password: {password}")
            else:
                # We have multiple solutions - with a 32-char password, we should have few collisions
                # Just take the first one and hope; if wrong, we'll reconnect
                print(f"Multiple solutions found: {len(solutions)}")
                # Print all for debugging
                for i, (start, pwd) in enumerate(solutions):
                    print(f"  Solution {i}: start={start}, pwd={pwd}")
                password = solutions[0][1]
            
            # Wait for password prompt and send password
            r.recvuntil(b'password: ')
            r.sendline(password.encode())
            
            # Check result
            result = r.recvline().decode().strip()
            print(f"Result: {result}")
            
            if result != 'correct':
                print("Failed! Will reconnect and try again.")
                success = False
                break
        
        if success:
            # Get the flag
            flag = r.recvline().decode().strip()
            print(f"FLAG: {flag}")
            r.close()
            break
        
        r.close()
    except Exception as e:
        print(f"Connection error: {e}")
        continue
