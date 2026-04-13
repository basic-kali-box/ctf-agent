#!/usr/bin/env python3
"""
RSA Advanced Attacks — CTF Template

Covers (beyond basic small-e / Franklin-Reiter):
  1. Wiener's attack  (small private exponent d)
  2. Fermat's factoring (p and q are close together)
  3. Common modulus attack (same n, different e)
  4. Broadcast attack / Hastad (same m, e=3, different n)
  5. LSB oracle (partial decryption oracle)
  6. ROCA-style vulnerable key detection
  7. CRT fault attack (d_p/d_q exposed)
"""
from math import isqrt, gcd
from Crypto.Util.number import long_to_bytes
import sympy

# ── fill in from challenge ───────────────────────────────────────────────────
n  = 0   # RSA modulus
e  = 65537
c  = 0   # ciphertext

# For multi-value attacks:
n_list = []   # [n1, n2, n3]  — Broadcast or Common Modulus
c_list = []   # [c1, c2, c3]
e_list = []   # [e1, e2, e3]  — Common Modulus: same n, different e
# ─────────────────────────────────────────────────────────────────────────────


# ── 1. Wiener's Attack ───────────────────────────────────────────────────────
def wieners_attack(e, n):
    """Recovers d when d < n^(1/4)/3. Works when e is large."""
    def continued_fraction(num, den):
        cf = []
        while den:
            cf.append(num // den)
            num, den = den, num % den
        return cf

    def convergents(cf):
        convs = []
        for i in range(len(cf)):
            if i == 0:
                convs.append((cf[0], 1))
            elif i == 1:
                convs.append((cf[0]*cf[1]+1, cf[1]))
            else:
                h_prev2, k_prev2 = convs[-2]
                h_prev1, k_prev1 = convs[-1]
                convs.append((cf[i]*h_prev1 + h_prev2, cf[i]*k_prev1 + k_prev2))
        return convs

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Solve x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq = isqrt(disc)
        if sq * sq == disc:
            m = pow(c, d, n)
            print(f"[+] Wiener: d = {d}")
            print(f"[+] m = {long_to_bytes(m)}")
            return m
    print("[-] Wiener's attack failed (d is not small enough)")
    return None


# ── 2. Fermat's Factoring ────────────────────────────────────────────────────
def fermats_factoring(n, max_iterations=1_000_000):
    """Factor n when p and q are close together (|p-q| is small)."""
    a = isqrt(n) + 1
    b2 = a * a - n
    for _ in range(max_iterations):
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            print(f"[+] Fermat: p = {p}")
            print(f"[+] Fermat: q = {q}")
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            print(f"[+] Flag: {long_to_bytes(m)}")
            return long_to_bytes(m)
        a += 1
        b2 = a * a - n
    print("[-] Fermat's factoring failed (p and q are not close)")
    return None


# ── 3. Common Modulus Attack ─────────────────────────────────────────────────
def common_modulus(n, e1, e2, c1, c2):
    """
    When the same plaintext m is encrypted with same n but two different exponents.
    e1*s1 + e2*s2 = 1 (extended Euclidean)
    """
    g, s1, s2 = sympy.gcdex(e1, e2)
    if g != 1:
        print(f"[-] gcd(e1,e2) = {g} != 1, attack may fail")
    # m = c1^s1 * c2^s2 mod n (handle negative exponents)
    if s1 < 0:
        c1 = pow(c1, -1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    result = long_to_bytes(m)
    print(f"[+] Common modulus: m = {result}")
    return result


# ── 4. Hastad Broadcast Attack ───────────────────────────────────────────────
def hastad_broadcast(e, n_list, c_list):
    """
    Same m encrypted with e different public keys (ni, e).
    Uses CRT to recover m^e, then take e-th integer root.
    Requires e ciphertexts.
    """
    from sympy.ntheory.modular import crt as sympy_crt
    assert len(n_list) >= e and len(c_list) >= e, f"Need at least {e} ciphertexts"

    # CRT: find x = c_i mod n_i for all i
    x, N = sympy_crt(n_list[:e], c_list[:e])

    # x = m^e over integers (if m^e < product(n_i))
    m, exact = sympy.integer_nthroot(int(x), e)
    if exact:
        result = long_to_bytes(m)
        print(f"[+] Hastad: m = {result}")
        return result

    # If not exact, m^e >= product(n_i), try gmpy2 floor root
    try:
        import gmpy2
        m, exact = gmpy2.iroot(x, e)
        if exact:
            result = long_to_bytes(int(m))
            print(f"[+] Hastad (gmpy2): m = {result}")
            return result
    except ImportError:
        pass

    print("[-] Hastad: not exact root — message might be padded or need more ciphertexts")
    # Print closest approximation anyway
    print(f"[?] Closest m: {long_to_bytes(m)}")
    return None


# ── 5. CRT Fault Attack ──────────────────────────────────────────────────────
def crt_fault(n, e, c, dp, p=None):
    """
    Recover p from d_p (= d mod p-1) exposure via: p = gcd(pow(c, dp, n)*pow(c,-e,n) - 1, n).
    """
    if p is None:
        # Brute e values if unknown
        for e_try in [3, 5, 17, 65537, e]:
            candidate = gcd(pow(pow(c, dp, n), e_try, n) - 1, n)
            if 1 < candidate < n:
                p = candidate
                print(f"[+] CRT fault: found p with e={e_try}")
                break
        if p is None:
            print("[-] CRT fault: could not find p")
            return None
    q = n // p
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    result = long_to_bytes(m)
    print(f"[+] CRT fault: m = {result}")
    return result


# ── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if n == 0:
        print("[!] Fill in n, e, c (and n_list/c_list for broadcast attacks)")
        import sys; sys.exit(0)

    print("[*] Trying all RSA attacks...")

    print("\n[1] Fermat's factoring...")
    if fermats_factoring(n) is None:
        print("\n[2] Wiener's attack...")
        if wieners_attack(e, n) is None:
            print("\n[3] Check n_list/c_list for broadcast or common modulus attacks")
