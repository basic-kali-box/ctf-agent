#!/usr/bin/env sage

n = 5113166966960118603250666870544315753374750136060769465485822149528706374700934720443689630473991177661169179462100732951725871457633686010946951736764639
c = 329402637167950119278220170950190680807120980712143610290182242567212843996710001488280098771626903975534140478814872389359418514658167263670496584963653
cor_m = 724154397787031699242933363312913323086319394176220093419616667612889538090840511507392245976984201647543870740055095781645802588721

print(f"n bits: {n.nbits()}")
print(f"c bits: {c.nbits()}")
print(f"cor_m bits: {cor_m.nbits()}")

# We have: (cor_m + r)^2 ≡ c (mod n)
# So: r^2 + 2*cor_m*r + (cor_m^2 - c) ≡ 0 (mod n)

# Define polynomial f(r) = (cor_m + r)^2 - c
R.<r> = PolynomialRing(Zmod(n))
f = (cor_m + r)^2 - c

print(f"\nPolynomial: f(r) = {f}")

# r is 160 bits, so bound X = 2^160
X = 2^160
print(f"\nBound X = 2^160 = {X}")
print(f"X bits: {X.nbits()}")

# Use Coppersmith's method to find small roots
print("\nTrying Coppersmith's method...")
roots = f.small_roots(X=X, beta=0.5)
print(f"Found roots: {roots}")

if roots:
    for root in roots:
        r_val = int(root)
        print(f"\nCandidate r = {r_val}")
        print(f"r bits: {r_val.bit_length()}")
        
        # Compute m = cor_m + r
        m = cor_m + r_val
        print(f"m = cor_m + r = {m}")
        
        # Verify: m^2 mod n should equal c
        if pow(m, 2, n) == c:
            print("✓ Verification passed: m^2 ≡ c (mod n)")
            
            # Convert m to bytes (flag)
            try:
                flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                print(f"Flag bytes: {flag_bytes}")
                print(f"Flag (hex): {flag_bytes.hex()}")
                print(f"Flag (ASCII): {flag_bytes.decode('ascii', errors='ignore')}")
            except Exception as e:
                print(f"Error converting to bytes: {e}")
        else:
            print("✗ Verification failed")