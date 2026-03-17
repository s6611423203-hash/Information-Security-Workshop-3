# Blockchain Voting System — Cryptographic Security Module
**Assignment 3: Phase 2 | Kiattisak Buasorn | 6611423203**

## Overview
Python implementation of a cryptographically secure ballot storage system for a Blockchain-based voting platform.

## Cryptographic Stack
| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Data Encryption | AES-256-GCM (AEAD) | NIST SP 800-38D |
| Digital Signature | ECDSA P-256 | FIPS 186-4 |
| Password Hashing | PBKDF2-HMAC-SHA256 (100,000 iter) | NIST SP 800-132 |
| Key Derivation | PBKDF2-HMAC-SHA256 (310,000 iter) | Student-ID Seeded |
| Integrity Check | HMAC-SHA256 per DB row | RFC 2104 |

## Student Fingerprint
```
[6611423203]-[0230c523ec41765c]
```
This fingerprint is derived exclusively from Student ID + Name,
ensuring every student produces unique ciphertext.

## Setup
```bash
pip install -r requirements.txt
python blockchain_voting_crypto.py
```

## Module Structure
```
blockchain_voting_crypto.py
├── StudentSeededKeyFactory   # M0: Key derivation from Student ID + Name
├── AES256GCMVaultService     # M1: AES-256-GCM encryption/decryption
├── ECCVoterIdentityService   # M2: ECDSA P-256 sign/verify
├── PasswordHashingService    # M3: Salted + Peppered SHA-256
├── SecureVotingDatabase      # M4: SQLite + HMAC integrity
└── TamperSimulator           # M5: Phase 4 pentest helper
```

## Security Notes
- `voting_secure.db` is listed in `.gitignore` — never commit DB files
- Private keys are generated in-memory only, never persisted to disk
- All PII is encrypted before storage; Blockchain layer stores only anonymous hashes
