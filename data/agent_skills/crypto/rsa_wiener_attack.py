"""
SKILL: rsa_wiener_attack
DESCRIPTION: Wiener's attack on RSA with small private exponent d.
PARAMETERS: n (int), e (int)
RETURNS: d (int) or None
REQUIRES: pip install owiener
TAGS: crypto, rsa, wiener
"""
import sys
from Crypto.Util.number import long_to_bytes

def attack(n, e, c=None):
    try:
        import owiener
    except ImportError:
        print("[!] owiener not installed. Run: pip install owiener")
        return None
        
    d = owiener.attack(e, n)
    if d is None:
        print("[!] Wiener attack failed. d not small enough or n/e invalid.")
        return None
        
    print(f"[*] Found private exponent d: {d}")
    
    if c is not None:
        m = pow(c, d, n)
        plaintext = long_to_bytes(m)
        print(f"[*] Plaintext (bytes): {plaintext}")
        try:
            print(f"[*] Plaintext (string): {plaintext.decode('utf-8')}")
        except Exception:
            pass
        return plaintext
    return d

if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        print("Usage: python rsa_wiener_attack.py <n> <e> [c]")
        sys.exit(1)
        
    n = int(sys.argv[1])
    e = int(sys.argv[2])
    c = int(sys.argv[3]) if len(sys.argv) == 4 else None
    
    attack(n, e, c)