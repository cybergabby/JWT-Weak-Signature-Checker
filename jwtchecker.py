"""
JWT Weak-Signature Checker / Decoder
===================================

Single-file Python CLI tool you can drop into a GitHub repo.

Features:
- Decode JWT header & payload without verification
- Detect `alg: none` vulnerability
- Quick check for weak HMAC (HS256) secrets using a wordlist
- Optionally try a public key or provided string as HMAC secret (RSA->HMAC confusion check)
- Produce a compact report and example PoC header/payload outputs

Dependencies:
- PyJWT (pip install pyjwt)

Usage examples:
- Decode only:
    python jwt_weak_signature_checker.py --token <JWT>

- Check for alg=none and weak HMAC keys using a wordlist:
    python jwt_weak_signature_checker.py --token <JWT> --wordlist wordlist.txt

- Try a public key (PEM file) as HMAC secret (confusion test):
    python jwt_weak_signature_checker.py --token <JWT> --pubkey public.pem

- Quick built-in small wordlist brute-force (fast test):
    python jwt_weak_signature_checker.py --token <JWT> --quick

Notes / Safety:
- Only test tokens you own or have explicit permission to inspect/attack.
- Brute-forcing production tokens may be illegal and unethical without authorization.

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

# Small builtin quick wordlist for fast checks
QUICK_WORDS = [
    "secret",
    "password",
    "123456",
    "admin",
    "jwtsecret",
    "changeme",
    "letmein",
    "default",
]


def b64url_decode(input_str: str) -> bytes:
    padding = '=' * ((4 - len(input_str) % 4) % 4)
    return base64.urlsafe_b64decode(input_str + padding)


def decode_no_verify(token: str) -> dict:
    """Decode header and payload without signature verification."""
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
    except ValueError:
        raise ValueError("Token does not look like a JWT (missing parts)")

    header = json.loads(b64url_decode(header_b64).decode('utf-8', errors='ignore') or '{}')
    payload = json.loads(b64url_decode(payload_b64).decode('utf-8', errors='ignore') or '{}')
    signature = signature_b64
    return {"header": header, "payload": payload, "signature": signature}


def check_alg_none(header: dict, signature: str) -> bool:
    alg = header.get('alg', '').lower()
    if alg == 'none':
        # signature should be empty for alg none
        return signature == '' or signature == 'null' or signature == '0'
    return False


def try_verify_hs256(token: str, secret: str) -> bool:
    """Attempt to verify token using HS256 with the provided secret.
    Returns True if verification succeeds.
    """
    try:
        jwt.decode(token, key=secret, algorithms=['HS256'], options={"verify_aud": False})
        return True
    except InvalidSignatureError:
        return False
    except DecodeError:
        return False
    except Exception:
        return False


def load_wordlist(path: str) -> List[str]:
    words = []
    if not os.path.exists(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            w = line.strip()
            if w:
                words.append(w)
    return words


def try_bruteforce_hs256(token: str, candidates: List[str], max_tries: Optional[int] = None) -> Optional[str]:
    tries = 0
    for secret in candidates:
        tries += 1
        if max_tries and tries > max_tries:
            break
        if try_verify_hs256(token, secret):
            return secret
    return None


def read_pem_as_secret(path: str) -> str:
    with open(path, 'rb') as f:
        data = f.read()
    # Using raw PEM bytes or stripped base64 may both work as a crude secret
    return data.decode('utf-8', errors='ignore')


def print_report(token: str, header: dict, payload: dict, signature: str, findings: List[str]) -> None:
    print('\n==== JWT INSPECTION REPORT ====')
    print('\n[Header]')
    print(json.dumps(header, indent=2))
    print('\n[Payload]')
    print(json.dumps(payload, indent=2))
    print('\n[Signature (b64url)]')
    print(signature)
    print('\n[Findings]')
    if findings:
        for i, f in enumerate(findings, 1):
            print(f"{i}. {f}")
    else:
        print('No obvious weaknesses detected with the provided checks.')
    print('\n===============================\n')


def main():
    parser = argparse.ArgumentParser(description='JWT Decoder & Weak-Signature Checker')
    parser.add_argument('--token', '-t', required=True, help='JWT token string')
    parser.add_argument('--wordlist', '-w', help='Path to wordlist for HS256 brute-force')
    parser.add_argument('--pubkey', '-p', help='Path to public key PEM file to try as HMAC secret')
    parser.add_argument('--quick', action='store_true', help='Run quick builtin wordlist checks')
    parser.add_argument('--max-tries', type=int, default=200000, help='Max tries when using large wordlist (default: 200000)')

    args = parser.parse_args()

    token = args.token.strip()

    try:
        info = decode_no_verify(token)
    except Exception as e:
        print(f"[!] Failed to decode token: {e}")
        sys.exit(1)

    header = info['header']
    payload = info['payload']
    signature = info['signature']

    findings = []

    # Check alg none
    if check_alg_none(header, signature):
        findings.append('Token uses alg=none; signature is empty. Token would be accepted if the server incorrectly allows alg=none')

    alg = header.get('alg', '').upper()
    print(f"[i] Detected alg: {alg}")

    # Quick builtin wordlist check
    if args.quick:
        print('[i] Running quick builtin wordlist check...')
        secret = try_bruteforce_hs256(token, QUICK_WORDS, max_tries=args.max_tries)
        if secret:
            findings.append(f'HS256 secret found using quick list: {secret}')
        else:
            print('[i] Quick list did not find a secret')

    # Wordlist brute-force if provided
    if args.wordlist:
        print(f"[i] Loading wordlist from: {args.wordlist}...")
        try:
            words = load_wordlist(args.wordlist)
        except Exception as e:
            print(f"[!] Failed to load wordlist: {e}")
            sys.exit(1)
        print(f"[i] Starting brute-force with {len(words)} candidates (max tries={args.max_tries})...")
        found = try_bruteforce_hs256(token, words, max_tries=args.max_tries)
        if found:
            findings.append(f'HS256 secret found in provided wordlist: {found}')
        else:
            print('[i] Provided wordlist did not find a matching secret')

    # Public key confusion test
    if args.pubkey:
        print(f"[i] Reading public key PEM from: {args.pubkey}")
        try:
            pem_secret = read_pem_as_secret(args.pubkey)
            if try_verify_hs256(token, pem_secret):
                findings.append('Token verified using the provided public key PEM as an HMAC secret (possible RSA<->HMAC confusion)')
            else:
                print('[i] Public key PEM did not verify token as HMAC secret')
        except Exception as e:
            print(f"[!] Failed to read public key file: {e}")

    # Extra heuristics: if alg is RS256 but signature verifies with empty secret or common secret
    if alg == 'RS256':
        print('[i] Token signed with RS256 — testing common HMAC heuristics (quick list)...')
        found = try_bruteforce_hs256(token, QUICK_WORDS, max_tries=1000)
        if found:
            findings.append('RS256 token accepted when verified as HS256 with a common secret (possible verification misconfiguration)')

    print_report(token, header, payload, signature, findings)

 if alg == "none":
    if signature != "":
        print("[!] Security Issue: alg=none but signature present — token integrity broken.")
    print("[!] Critical: alg=none tokens are insecure and should not be accepted.")



if __name__ == '__main__':
    main()

