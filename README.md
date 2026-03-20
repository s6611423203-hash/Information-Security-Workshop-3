# Blockchain Voting System — Cryptographic Security Module
**Workshop 3: Designing Operational System Security | Kiattisak Buasorn | 6611423203**

## ภาพรวมระบบ

โปรเจคนี้เป็นระบบโหวต (Voting System) ที่เน้นความปลอดภัยสูง โดยใช้เทคนิคทาง Cryptography เพื่อป้องกัน:

การปลอมแปลงข้อมูล

การแก้ไขข้อมูลย้อนหลัง

การเข้าถึงข้อมูลส่วนตัว

ข้อมูลสำคัญ เช่น ชื่อ, เลขบัตรประชาชน และผลโหวต จะถูกเข้ารหัสทั้งหมดก่อนเก็บลงฐานข้อมูล

## เทคโนโลยีที่ใช้ (Cryptographic Stack)
| ส่วน | อัลกอริทึม | หน้าที่ |
|-----------|-----------|----------|
| เข้ารหัสข้อมูล | AES-256-GCM (AEAD) | ป้องกันข้อมูลรั่วไหล |
| ลายเซ็นดิจิทัล | ECDSA P-256 | ยืนยันตัวตนผู้โหวต |
|รหัสผ่าน | PBKDF2-HMAC-SHA256 (100,000 iter) | ป้องกันการเดารหัส |
| สร้างกุญแจ | PBKDF2-HMAC-SHA256 (310,000 iter) | ทำให้แต่ละคนได้ key ไม่เหมือนกัน |
| ตรวจสอบข้อมูล | HMAC-SHA256 per DB row |ป้องกันข้อมูลถูกแก้ |

## Student Fingerprint
```
[6611423203]-[0230c523ec41765c]
```
This fingerprint is derived exclusively from Student ID + Name,
ensuring every student produces unique ciphertext.

## Setup
```bash
pip3 install -r requirements.txt
python3 blockchain_voting_crypto.py
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
