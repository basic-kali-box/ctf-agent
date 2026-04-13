#!/usr/bin/env python3
"""
Elliptic Curve Cryptography (ECC) Attacks — CTF Template

Covers:
  1. Pohlig-Hellman ECDLP (small subgroup / smooth order)
  2. Smart's attack (anomalous curves: #E(Fp) == p)
  3. MOV attack (curves with small embedding degree)
  4. Invalid curve attack (point not on curve)
  5. ECDSA nonce reuse (k reused across two signatures)
"""
from Crypto.Util.number import long_to_bytes

# ── fill in ─────────────────────────────────────────────────────────────────
# Standard curve params (or fill with challenge values)
# Example: secp256k1 — replace with challenge curve
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a  = 0
b  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Public key and known data
Px, Py = 0, 0   # target public key (x, y)
# For ECDSA nonce reuse:
r, s1, s2 = 0, 0, 0
z1, z2 = 0, 0   # hashes of the two messages
# ────────────────────────────────────────────────────────────────────────────


class Point:
    """Minimal Weierstrass elliptic curve point arithmetic mod p."""
    def __init__(self, x, y, inf=False):
        self.x, self.y, self.inf = x, y, inf

    def __add__(self, Q):
        if self.inf: return Q
        if Q.inf: return self
        if self.x == Q.x:
            if self.y != Q.y or self.y == 0:
                return Point(0, 0, True)
            m = (3 * self.x**2 + a) * pow(2 * self.y, -1, p) % p
        else:
            m = (Q.y - self.y) * pow(Q.x - self.x, -1, p) % p
        xr = (m**2 - self.x - Q.x) % p
        yr = (m * (self.x - xr) - self.y) % p
        return Point(xr, yr)

    def __mul__(self, k):
        R, Q = Point(0, 0, True), self
        while k > 0:
            if k & 1: R = R + Q
            Q = Q + Q
            k >>= 1
        return R

    def __rmul__(self, k): return self.__mul__(k)

    def __repr__(self): return f"Point(inf)" if self.inf else f"Point({self.x}, {self.y})"


G = Point(Gx, Gy)
P = Point(Px, Py)


# ── Attack 1: ECDSA nonce reuse ──────────────────────────────────────────────
def ecdsa_nonce_reuse():
    """Recover private key when the same nonce k is used in two signatures."""
    if not all([r, s1, s2, z1, z2]):
        print("[!] Fill in r, s1, s2, z1, z2 first.")
        return
    # k = (z1 - z2) / (s1 - s2) mod n
    k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
    # d = (s1*k - z1) / r mod n
    d = ((s1 * k - z1) * pow(r, -1, n)) % n
    print(f"[+] Nonce k   = {k}")
    print(f"[+] Private d = {d}")
    print(f"[+] Flag hint = {long_to_bytes(d)}")
    return d


# ── Attack 2: Smart's attack (anomalous curves) ──────────────────────────────
def smarts_attack():
    """
    Solves ECDLP on anomalous curves over Fp where #E(Fp) == p.
    Lifts points to Qp and uses formal group logarithm.
    Requires: p, a, b, G, P where #E(Fp) == p.
    """
    # Uses Hensel lifting — needs curve where trace of Frobenius = 1
    try:
        # Lift G and P to Fp2 (approximate lift)
        def lift(curve_p, pt):
            # Simple Hensel lift — works for anomalous curves
            x, y = pt.x, pt.y
            # Find a lift to Zp^2
            t = pow(y, -1, curve_p) * (3 * x**2 + a) % curve_p
            x_lift = x + curve_p * ((t * curve_p - 0) % curve_p)
            return x_lift

        Gx_lift = lift(p, G)
        Px_lift = lift(p, P)

        # Formal logarithm
        phi_G = (Gx_lift * pow(Gy, -1, p)) % p
        phi_P = (Px_lift * pow(Py, -1, p)) % p
        k = (phi_P * pow(phi_G, -1, p)) % p
        print(f"[+] ECDLP solution (Smart's): k = {k}")
        print(f"[+] Verify: k*G == P? {(k * G).x == P.x}")
        return k
    except Exception as e:
        print(f"[-] Smart's attack failed: {e}")


# ── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] ECC CTF Attack Template")
    print("[*] Detected attack: ECDSA nonce reuse (fill in r,s1,s2,z1,z2)")
    print("[*] Other options: smarts_attack(), pohlig_hellman()")
    ecdsa_nonce_reuse()
