#!/usr/bin/env python3
"""
Franklin-Reiter Related Message Attack
Recovers m when: c1 = m^e mod n  AND  c2 = f(m)^e mod n
where f(x) = a*x + b is a known linear function.

Common CTF patterns:
  m2 = m1 >> 8       →  m1 = 256*m2 + last_byte   (a=256, b=last_byte)
  m2 = m1 - k        →  m1 = m2 + k                (a=1, b=k)
  m2 = m1 XOR const  →  NOT linear — use different attack

No Sage required. Pure Python polynomial GCD over Z_n.
"""
from Crypto.Util.number import long_to_bytes

# ── fill in ───────────────────────────────────────────────────────────────────
n  = 0   # RSA modulus
e  = 5   # public exponent (must be small)
c1 = 0   # ciphertext of m1
c2 = 0   # ciphertext of m2

# Linear relation: m1 = a*m2 + b
# For m2 = m1 >> 8:  a=256, b = last byte of m1
# Guess b from flag format — for most CTFs: ord('}') = 125.
# Set b = 0 to brute-force all 256 values automatically.
a = 256
b = 125   # set to 0 to brute-force
# ─────────────────────────────────────────────────────────────────────────────


# ── polynomial arithmetic over Z_n ───────────────────────────────────────────

def poly_mul(p1, p2):
    """Multiply two polynomials mod n. Coeffs: [a0, a1, ..., ad] (low→high)."""
    r = [0] * (len(p1) + len(p2) - 1)
    for i, a in enumerate(p1):
        for j, b in enumerate(p2):
            r[i + j] = (r[i + j] + a * b) % n
    return r


def poly_pow(p, exp):
    r = [1]
    for _ in range(exp):
        r = poly_mul(r, p)
    return r


def poly_trim(p):
    while p and p[-1] == 0:
        p.pop()
    return p or [0]


def poly_divmod(p1, p2):
    r = list(p1)
    p2 = poly_trim(list(p2))
    poly_trim(r)
    if len(r) < len(p2):
        return [0], r
    q = []
    while len(r) >= len(p2):
        lc = r[-1]
        g = __import__('math').gcd(lc, n)
        if g != 1:
            raise ValueError(f"[!] Found factor of n while computing GCD: {g}")
        inv = pow(lc, -1, n)
        c = (lc * inv) % n  # = 1, just normalises; real coeff below
        # leading coeff of r divided by leading coeff of p2
        lc_p2 = p2[-1]
        g2 = __import__('math').gcd(lc_p2, n)
        if g2 != 1:
            raise ValueError(f"[!] Found factor of n: {g2}")
        inv_p2 = pow(lc_p2, -1, n)
        coeff = (lc * inv_p2) % n
        q.insert(0, coeff)
        shift = len(r) - len(p2)
        for i, v in enumerate(p2):
            r[shift + i] = (r[shift + i] - coeff * v) % n
        poly_trim(r)
    return q, r


def poly_gcd(p1, p2):
    p1, p2 = poly_trim(list(p1)), poly_trim(list(p2))
    while any(c != 0 for c in p2):
        _, r = poly_divmod(p1, p2)
        p1, p2 = p2, poly_trim(r)
    return p1


# ── attack ────────────────────────────────────────────────────────────────────

def franklin_reiter(try_b=None):
    target_b = try_b if try_b is not None else b
    # g1(x) = x^e - c2  (root: m2)
    g1 = [(-c2) % n] + [0] * (e - 1) + [1]

    # g2(x) = (a*x + b)^e - c1  (root: m2, since m1 = a*m2 + b)
    g2 = poly_pow([target_b % n, a % n], e)
    g2[0] = (g2[0] - c1) % n

    common = poly_gcd(g1, g2)

    if len(common) == 2:
        # common = [c0, c1_coeff] → c1_coeff*x + c0 = 0 → x = -c0 / c1_coeff
        inv = pow(common[1], -1, n)
        m2_val = (-common[0] * inv) % n
        m1_val = (a * m2_val + target_b) % n
        return m1_val
    elif len(common) == 1:
        # Degenerate — might mean gcd is a constant (attack failed for this b)
        return None
    else:
        # Higher degree — shouldn't happen with correct params
        print(f"[!] GCD degree {len(common)-1} — unexpected")
        return None


def _looks_like_flag(data: bytes) -> bool:
    """Returns True if bytes look like a CTF flag (printable ASCII with a {..} structure)."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return False
    FLAG_PREFIXES = (
        "flag{", "FLAG{", "CTF{", "ctf{",
        "HTB{", "htb{", "picoCTF{",
        "AKASEC{", "ENSA{", "ENSET{",
        "TSTCTF{", "FCSC{", "DCTF{",
    )
    return any(text.startswith(p) for p in FLAG_PREFIXES) or \
           (text.isprintable() and "{" in text and text.endswith("}"))


if __name__ == "__main__":
    if b != 0:
        # Try single known last-byte value
        m = franklin_reiter()
        if m:
            result = long_to_bytes(m)
            print("[+] m1 =", result)
        else:
            print(f"[-] Attack failed with b={b}. Try setting b=0 to brute-force.")
    else:
        # Brute-force b (last byte of m1) over all 256 values
        print("[*] Brute-forcing last byte (b=0..255)...")
        found = False
        for guess_b in range(256):
            try:
                m = franklin_reiter(try_b=guess_b)
                if m:
                    try:
                        text = long_to_bytes(m)
                        print(f"[?] b={guess_b}: {text}")
                        if _looks_like_flag(text):
                            print(f"[+] FLAG FOUND with b={guess_b}: {text}")
                            found = True
                            break
                    except Exception:
                        pass
            except ValueError as e:
                print(f"[!] b={guess_b}: {e}")
                break
        if not found:
            print("[-] No flag found after brute-forcing all 256 values.")
