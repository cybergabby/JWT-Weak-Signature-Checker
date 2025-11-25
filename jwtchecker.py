"""
JWT Weak-Signature Checker / Decoder
===================================

Single-file Python CLI tool you can drop into a GitHub repo.

Features:
- Decode JWT header & payload without verification
- Detect `alg: none` vulnerabilities (including signature mismatch)
- Quick check for weak HMAC (HS256) secrets using a wordlist
- Optional RSA→HMAC confusion test
- Clean, professional inspection report

Dependencies:
- PyJWT (pip install pyjwt)
"""

import argparse
import base64
import json
import sys
import os
from typing import Optional, List

try:
    import jwt
    from jwt import InvalidSignatureError, DecodeError
except Exception:
    print("[!] Missing dependency: install with `pip install PyJWT`")
    raise

# Small builtin quick wordlist
QUICK_WORDS = [
    "secret", "password", "123456", "admin",
    "jwtsecret", "changeme", "letmein", "default"
]

# -----------------------------
# Base64 URL decoding helper
# -----------------------------
def b64url_decode(input_str: str) -> bytes:
    padding = '=' * ((4 - len(input_str) % 4) % 4)
    return base64.urlsafe_b64decode(input_str + padding)

# -----------------------------
# Decode header/payload only
# -----------------------------
def decode_no_verify(token: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
    except ValueError:
        raise ValueError("Token does not look like a JWT (missing parts)")

    header = json.loads(b64url_decode(header_b64).decode('utf-8', errors='ignore') or '{}')
    payload = json.loads(b64url_decode(payload_b64).decode('utf-8', errors='ignore') or '{}')
    signature = signature_b64
    return {"header": header, "payload": payload, "signature": signature}

# -----------------------------
# Weak HS256 signature checker
# -----------------------------
def try_verify_hs256(token: str, secret: str) -> bool:
    try:
        jwt.decode(token, key=secret, algorithms=['HS256'], options={"verify_aud": False})
        return True
    except (InvalidSignatureError, DecodeError):
        return False
    except Exception:
        return False

# -----------------------------
# Load wordlist
# -----------------------------
def load_wordlist(path: str) -> List[str]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

# -----------------------------
# Bruteforce HS256
# -----------------------------
def try_bruteforce_hs256(token: str, candidates: List[str], max_tries: Optional[int] = None) -> Optional[str]:
    tries = 0
    for secret in candidates:
        tries += 1
        if max_tries and tries > max_tries:
            break
        if try_verify_hs256(token, secret):
            return secret
    return None

# -----------------------------
# Read PEM key as secret (confusion test)
# -----------------------------
def read_pem_as_secret(path: str) -> str:
    with open(path, 'rb') as f:
        return f.read().decode('utf-8', errors='ignore')

# -----------------------------
# Report printer
# -----------------------------
def print_report(token: str, header: dict, payload: dict, signature: str, findings: List[str]) -> None:
    print("\n==== JWT INSPECTION REPORT ====")
    print("\n[Header]")
    print(json.dumps(header, indent=2))
    print("\n[Payload]")
    print(json.dumps(payload, indent=2))
    print("\n[Signature (b64url)]")
    print(signature)
    print("\n[Findings]")
    if findings:
        for i, f in enumerate(findings, 1):
            print(f"{i}. {f}")
    else:
        print("No obvious weaknesses detected with the provided checks.")
    print("\n===============================\n")

# -----------------------------
# Main logic
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description='JWT Decoder & Weak-Signature Checker')
    parser.add_argument('--token', '-t', required=True, help='JWT token string')
    parser.add_argument('--wordlist', '-w', help='Path to wordlist for HS256 brute-force')
    parser.add_argument('--pubkey', '-p', help='Path to public key PEM file to try as HMAC secret')
    parser.add_argument('--quick', action='store_true', help='Run quick builtin wordlist checks')
    parser.add_argument('--max-tries', type=int, default=200000, help='Max brute-force attempts (default: 200000)')
    args = parser.parse_args()

    token = args.token.strip()

    try:
        info = decode_no_verify(token)
    except Exception as e:
        print(f"[!] Failed to decode token: {e}")
        sys.exit(1)

    header = info["header"]
    payload = info["payload"]
    signature = info["signature"]

    findings = []

    # -----------------------------
    # ALG NONE ATTACK DETECTION
    # -----------------------------
    alg = header.get("alg", "").lower()

    print(f"[i] Detected alg: {alg.upper()}")

    if alg == "none":
        findings.append("Token uses alg=none (critical vulnerability).")

        if signature and signature.strip() != "":
            findings.append("Signature present even though alg=none — token integrity is broken (downgrade/tampering risk).")
        else:
            findings.append("Unsigned token — trivially forgeable.")

    # -----------------------------
    # Quick wordlist
    # -----------------------------
    if args.quick:
        print("[i] Running quick builtin wordlist check...")
        secret = try_bruteforce_hs256(token, QUICK_WORDS, max_tries=args.max_tries)
        if secret:
            findings.append(f"HS256 secret cracked using quick list: {secret}")
        else:
            print("[i] Quick list did not find a secret")

    # -----------------------------
    # Custom wordlist
    # -----------------------------
    if args.wordlist:
        print(f"[i] Loading wordlist: {args.wordlist}")
        try:
            words = load_wordlist(args.wordlist)
        except Exception as e:
            print(f"[!] Wordlist load error: {e}")
            sys.exit(1)

        print(f"[i] Starting brute-force with {len(words)} candidates...")
        found = try_bruteforce_hs256(token, words, max_tries=args.max_tries)
        if found:
            findings.append(f"HS256 secret cracked from provided wordlist: {found}")
        else:
            print("[i] Wordlist did not reveal the secret")

    # -----------------------------
    # PEM confusion testing
    # -----------------------------
    if args.pubkey:
        print(f"[i] Testing RSA public key for HMAC confusion: {args.pubkey}")
        try:
            pem_secret = read_pem_as_secret(args.pubkey)
            if try_verify_hs256(token, pem_secret):
                findings.append("Token verified using a public key as an HMAC secret — RS256↔HS256 confusion vulnerability.")
            else:
                print("[i] Public key did not validate token as HS256.")
        except Exception as e:
            print(f"[!] PEM load error: {e}")

    # -----------------------------
    # RS256 confusion detection
    # -----------------------------
    if alg == "rs256":
        print("[i] Token is RS256 — checking for HS256 fallback misconfiguration...")
        found = try_bruteforce_hs256(token, QUICK_WORDS, max_tries=500)
        if found:
            findings.append("RS256 token accepted under HS256 using common secrets (misconfigured verification).")

    # -----------------------------
    # Print final report
    # -----------------------------
    print_report(token, header, payload, signature, findings)


if __name__ == '__main__':
    main()
