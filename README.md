# JWT-Weak-Signature-Checker

JWT Weak Signature Checker / Decoder

A lightweight Python offensive-security utility for inspecting JSON Web Tokens (JWTs), detecting signature-related misconfigurations, and brute-forcing weak HMAC secrets.
Optimized for AppSec Engineers, Pentesters, and Bug Bounty hunters.

# Features

Decode JWT header & payload without verification
Detect alg:none misconfiguration
Identify weak HS256 secrets using built-in or custom wordlists
Test public key confusion attacks (RSA → HMAC)
Generate a concise vulnerability report
Zero external infrastructure needed — single-file tool

# 🔧 Installation

Install dependency:
pip install pyjwt

Clone your repo and run:
python jwt_weak_signature_checker.py --help

Usage Examples
1. Decode only
   python jwt_weak_signature_checker.py --token <JWT>

2. Quick weak-secret check (built-in list)
   python jwt_weak_signature_checker.py --token <JWT> --quick

3. Full brute-force with wordlist
   python jwt_weak_signature_checker.py --token <JWT> --wordlist wordlist.txt

4. Public-key confusion test (RSA → HMAC)
   python jwt_weak_signature_checker.py --token <JWT> --pubkey public.pem

5. Limit brute-force attempts
   python jwt_weak_signature_checker.py --token <JWT> --wordlist rockyou.txt --max-tries 50000


# 📌 What This Tool Detects
Vulnerability	Description
-------------------------------------------------------------------------------------------------------------------------
alg:none acceptance                |	 Server accepts unsigned tokens.
Weak HS256 secrets	               |   Easily guessable or default secrets (secret, admin, changeme, etc.).
Public key as HMAC secret          |	 Misconfigured libraries that verify RS256 tokens with public keys as HMAC secrets.
RS256 → HS256 downgrade acceptance |   System incorrectly trusts HMAC versions of RSA tokens.
---------------------------------------------------------------------------------------------------------------------------


# Output Example
==== JWT INSPECTION REPORT ====

[Header]
{
  "alg": "HS256",
  "typ": "JWT"
}

[Payload]
{
  "user": "admin",
  "role": "superuser"
}

[Findings]
1. HS256 secret found using quick list: changeme

===============================

# ⚠️ Legal Notice

This tool is for authorized security testing only.
Do not use it on systems you do not own or have explicit permission to test.

📚 Why This Matters

Weak JWT signing practices still appear in:

Legacy applications
Misconfigured libraries
Internal enterprise APIs
Poorly implemented OAuth/OIDC workflows

This tool provides rapid offensive validation for pentests, bug bounties, and secure code reviews.

🤝 Contributions

PRs are welcome: feel free to improve algorithms, add new attack modules, or enhance documentation.

