"""
SKILL: rsa_small_e
DESCRIPTION: Solves RSA when e is very small (e.g. 3) and the message m is small enough that m^e < n.
PARAMETERS: c (int), e (int)
RETURNS: m (int) or bytes
TAGS: crypto, rsa, small_e, iroot
"""
import sys
from Crypto.Util.number import long_to_bytes
import gmpy2

def attack(c, e):
    gmpy2.get_context().precision = 2048
    m, exact = gmpy2.iroot(gmpy2.mpz(c), e)
    
    if exact:
        print("[*] Exact root found!")
        plaintext = long_to_bytes(int(m))
        print(f"[*] Plaintext (bytes): {plaintext}")
        try:
            print(f"[*] Plaintext (string): {plaintext.decode('utf-8')}")
        except Exception:
            pass
        return plaintext
    else:
        print("[!] Failed taking exact root. Message is either padded or m^e > n.")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python rsa_small_e.py <c> <e>")
        sys.exit(1)
        
    c = int(sys.argv[1])
    e = int(sys.argv[2])
    attack(c, e)
