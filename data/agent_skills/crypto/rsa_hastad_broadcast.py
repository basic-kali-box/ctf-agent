"""
SKILL: rsa_hastad_broadcast
DESCRIPTION: Recovers plaintext when same message is encrypted with small e (e=3,5,7) and different moduli.
PARAMETERS: ciphertexts list [(c1,n1), (c2,n2), ...], e (int)
RETURNS: m (int) decrypted message
TAGS: crypto, rsa, hastad, broadcast
"""
from functools import reduce
from Crypto.Util.number import long_to_bytes
import gmpy2

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * gmpy2.invert(p, n_i) * p
    return sum % prod

def attack(pairs, e):
    # pairs = [(c1, n1), (c2, n2), ...]
    c_list = [c for c, _ in pairs]
    n_list = [n for _, n in pairs]
    if len(pairs) < e:
        raise ValueError(f"Need at least {e} ciphertexts for e={e}")
    # Use first e pairs
    c_list = c_list[:e]
    n_list = n_list[:e]
    C = chinese_remainder(n_list, c_list)
    m, exact = gmpy2.iroot(C, e)
    if not exact:
        raise ValueError("Failed to compute exact e-th root.")
    return int(m)