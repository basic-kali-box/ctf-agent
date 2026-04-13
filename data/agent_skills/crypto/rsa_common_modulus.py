"""
SKILL: rsa_wiener_attack
DESCRIPTION: Wiener's attack on RSA with small private exponent d.
PARAMETERS: n (int), e (int)
RETURNS: d (int) or None
REQUIRES: pip install owiener
TAGS: crypto, rsa, wiener
"""
import sys

def attack(n, e):
    try:
        import owiener
    except ImportError:
        print("[!] owiener not installed. Run: pip install owiener")
        return None
    d = owiener.attack(e, n)
    if d is None:
        print("[!] Wiener attack failed. d not small enough or n/e invalid.")
    return d

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python rsa_wiener_attack.py <n> <e>")
        sys.exit(1)
    n = int(sys.argv[1])
    e = int(sys.argv[2])
    d = attack(n, e)
    if d:
        print(f"Private exponent d: {d}")