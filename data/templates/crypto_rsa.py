#!/usr/bin/env python3
"""
RSA attack toolkit — covers the most common CTF RSA scenarios.
Run with: python3 crypto_rsa.py
"""
from Crypto.Util.number import long_to_bytes, bytes_to_long
import math, sys

# ── fill these in ────────────────────────────────────────────────────────────
n = 0   # modulus
e = 0   # public exponent
c = 0   # ciphertext (integer)
# ─────────────────────────────────────────────────────────────────────────────


def small_e_cube_root():
    """e=3, no padding, m^3 < n → direct cube root."""
    try:
        from sympy import integer_nthroot
    except ImportError:
        sys.exit("pip install sympy")
    m, exact = integer_nthroot(c, e)
    if exact:
        print("[+] cube root attack:", long_to_bytes(m))
    else:
        # m^3 wrapped around n — try adding multiples of n
        for k in range(1, 10000):
            m, exact = integer_nthroot(c + k * n, e)
            if exact:
                print(f"[+] cube root (k={k}):", long_to_bytes(m))
                return
        print("[-] cube root failed")


def common_modulus(n, e1, e2, c1, c2):
    """Same n, two different exponents, same plaintext → GCD attack."""
    g, s1, s2 = extended_gcd(e1, e2)
    if g != 1:
        print("[-] gcd(e1,e2) != 1")
        return
    if s1 < 0:
        c1 = pow(mod_inverse(c1, n), -s1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(mod_inverse(c2, n), -s2, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    print("[+] common modulus:", long_to_bytes(m))


def wiener_attack():
    """Small private exponent (d < n^0.25) → Wiener's continued fractions."""
    try:
        from owiener import attack
    except ImportError:
        sys.exit("pip install owiener")
    d = attack(e, n)
    if d:
        m = pow(c, d, n)
        print("[+] Wiener d =", d, "→", long_to_bytes(m))
    else:
        print("[-] Wiener failed")


def factordb_attack():
    """Try to factor n via factordb.com API."""
    try:
        import requests
    except ImportError:
        sys.exit("pip install requests")
    r = requests.get(f"https://factordb.com/api?query={n}", timeout=10)
    data = r.json()
    print("[factordb]", data)
    factors = data.get("factors", [])
    if len(factors) == 2:
        p = int(factors[0][0])
        q = int(factors[1][0])
        print(f"[+] p={p}\n[+] q={q}")
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n)
        print("[+] flag:", long_to_bytes(m))


def decrypt_with_pq(p, q):
    """Direct decryption when you have p and q."""
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    print("[+] plaintext:", long_to_bytes(m))


# ── utilities ─────────────────────────────────────────────────────────────────
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def mod_inverse(a, m):
    _, x, _ = extended_gcd(a % m, m)
    return x % m


if __name__ == "__main__":
    print("e =", e)
    if e == 3:
        small_e_cube_root()
    elif e > 10**50:
        wiener_attack()
    else:
        factordb_attack()
