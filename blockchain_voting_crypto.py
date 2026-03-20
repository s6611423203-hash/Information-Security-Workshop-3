"""
=============================================================================
  Blockchain Voting System — Cryptographic Security Module
  Assignment 3: Phase 2 — Cryptographic Implementation
  
  ระบบนี้ประกอบด้วย:
    1. AES-256-GCM  — เข้ารหัสข้อมูลผู้โหวตในฐานข้อมูล
    2. ECC (ECDSA)  — Digital Signature ยืนยันตัวตนผู้ส่ง
    3. SHA-256      — Salting & Hashing รหัสผ่าน
    4. Student ID Seeding — Key ถูกสร้างจาก StudentID + ชื่อจริงเท่านั้น
    5. Integrity Checking — ตรวจจับการแก้ไขข้อมูลใน "DB"

  NOTE: แทนที่ STUDENT_ID และ STUDENT_NAME ด้วยข้อมูลจริงก่อน run
=============================================================================
"""

import os
import json
import hashlib
import hmac
import sqlite3
import datetime
from datetime import timezone
import base64
import secrets

from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# =============================================================================
# CONFIGURATION — แก้ค่านี้ตาม Student ID และชื่อจริง
# =============================================================================
STUDENT_ID   = "6611423203"
STUDENT_NAME = "Kiattisak Buasorn"
DB_PATH      = "voting_secure.db"

# =============================================================================
# MODULE 0: Student-ID-Seeded Key Derivation
# =============================================================================

class StudentSeededKeyFactory:
    """
    สร้าง Cryptographic Material จาก Student ID + Name เท่านั้น
    ทำให้ผลลัพธ์ของทุกคนไม่เหมือนกัน
    """

    def __init__(self, student_id: str, student_name: str):
        self.student_id   = student_id.strip()
        self.student_name = student_name.strip()
        self._master_seed = self._derive_master_seed()

    def _derive_master_seed(self) -> bytes:
        """
        Master Seed = PBKDF2-HMAC-SHA256(
            password = student_id || ':' || student_name,
            salt     = SHA256(student_name || student_id),
            iterations = 310_000   (NIST 2023 recommended minimum)
        )
        """
        password = f"{self.student_id}:{self.student_name}".encode("utf-8")
        salt_input = f"{self.student_name}{self.student_id}".encode("utf-8")
        salt = hashlib.sha256(salt_input).digest()  # 32-byte deterministic salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,           # 512-bit master key material
            salt=salt,
            iterations=310_000,
            backend=default_backend(),
        )
        master = kdf.derive(password)
        return master

    def get_aes_key(self) -> bytes:
        """AES-256 key = first 32 bytes of master seed"""
        return self._master_seed[:32]

    def get_hmac_key(self) -> bytes:
        """HMAC key = last 32 bytes of master seed"""
        return self._master_seed[32:]

    def get_password_global_pepper(self) -> bytes:
        """
        Global Pepper สำหรับ password hashing
        = SHA256(master_seed || 'pepper')
        """
        return hashlib.sha256(self._master_seed + b"pepper").digest()

    def get_student_fingerprint(self) -> str:
        """แสดง hex fingerprint เพื่อยืนยันว่า key ถูก seed ด้วย student identity"""
        fp = hashlib.sha256(self._master_seed).hexdigest()[:16]
        return f"[{self.student_id}]-[{fp}]"


# =============================================================================
# MODULE 1: AES-256-GCM Encryption for Database Records
# =============================================================================

class AES256GCMVaultService:
    """
    เข้ารหัส/ถอดรหัสข้อมูล Voter Record ด้วย AES-256-GCM
    - GCM mode ให้ Authenticated Encryption (confidentiality + integrity)
    - IV (Nonce) ขนาด 96-bit สร้างใหม่ทุก encryption operation
    - Associated Data (AAD) ผูก ciphertext กับ context (voter_id)
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 requires exactly 32-byte key")
        self._aesgcm = AESGCM(key)
        self.key_fingerprint = hashlib.sha256(key).hexdigest()[:12]

    def encrypt(self, plaintext: str, associated_data: str = "") -> dict:
        """
        Returns dict: {
          'iv_b64':         base64(96-bit nonce),
          'ciphertext_b64': base64(ciphertext + GCM auth tag),
          'aad_b64':        base64(associated_data),
          'algo':           'AES-256-GCM'
        }
        """
        iv  = secrets.token_bytes(12)   # 96-bit nonce — NIST SP 800-38D
        aad = associated_data.encode("utf-8")
        ct  = self._aesgcm.encrypt(iv, plaintext.encode("utf-8"), aad)

        return {
            "iv_b64":         base64.b64encode(iv).decode(),
            "ciphertext_b64": base64.b64encode(ct).decode(),
            "aad_b64":        base64.b64encode(aad).decode(),
            "algo":           "AES-256-GCM",
            "key_fp":         self.key_fingerprint,
        }

    def decrypt(self, encrypted_dict: dict) -> str:
        """ถอดรหัส + ตรวจสอบ GCM authentication tag อัตโนมัติ"""
        iv  = base64.b64decode(encrypted_dict["iv_b64"])
        ct  = base64.b64decode(encrypted_dict["ciphertext_b64"])
        aad = base64.b64decode(encrypted_dict["aad_b64"])
        pt  = self._aesgcm.decrypt(iv, ct, aad)  # raises InvalidTag if tampered
        return pt.decode("utf-8")


# =============================================================================
# MODULE 2: ECC Digital Signature (ECDSA P-256)
# =============================================================================

class ECCVoterIdentityService:
    """
    ใช้ ECDSA บน NIST P-256 curve สำหรับ Digital Signature
    - แต่ละ Voter มี keypair เป็นของตัวเอง
    - Signature ยืนยันว่า Ballot Submission มาจาก Voter จริง
    - Public Key จะถูกเก็บไว้ใน Voter Registry
    """

    @staticmethod
    def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """สร้าง ECDSA P-256 keypair สำหรับ Voter"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        return private_key, private_key.public_key()

    @staticmethod
    def sign_ballot(private_key: ec.EllipticCurvePrivateKey,
                    ballot_data: dict) -> str:
        """
        Sign ballot payload:
          message = SHA256(canonical JSON of ballot_data)
          signature = ECDSA(private_key, message)
        Returns base64-encoded DER signature
        """
        canonical = json.dumps(ballot_data, sort_keys=True, ensure_ascii=False)
        message   = canonical.encode("utf-8")
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode()

    @staticmethod
    def verify_ballot_signature(public_key: ec.EllipticCurvePublicKey,
                                ballot_data: dict,
                                signature_b64: str) -> bool:
        """
        ยืนยัน signature — คืน True ถ้า valid, False ถ้า tampered/invalid
        """
        try:
            canonical = json.dumps(ballot_data, sort_keys=True, ensure_ascii=False)
            message   = canonical.encode("utf-8")
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    @staticmethod
    def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
        """แปลง public key เป็น PEM string สำหรับเก็บใน DB"""
        pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode()

    @staticmethod
    def deserialize_public_key(pem_str: str) -> ec.EllipticCurvePublicKey:
        """โหลด public key จาก PEM string"""
        return serialization.load_pem_public_key(
            pem_str.encode(), backend=default_backend()
        )


# =============================================================================
# MODULE 3: Password Hashing — SHA-256 with Salting + Pepper
# =============================================================================

class PasswordHashingService:
    """
    รหัสผ่านถูก hash ด้วยขั้นตอน:
      1. สร้าง Salt แบบ random 32 bytes (per-user)
      2. นำ Pepper (global, จาก Student ID seed) ต่อท้าย password
      3. Hash = SHA-256 iterative (PBKDF2-like) 100,000 รอบ
      4. เก็บ: algorithm + iterations + salt_b64 + hash_b64
    """

    ITERATIONS = 100_000
    ALGO       = "SHA256-SALTED-PBKDF2"

    def __init__(self, global_pepper: bytes):
        self._pepper = global_pepper

    def hash_password(self, password: str) -> dict:
        """
        สร้าง salted hash สำหรับเก็บใน DB
        """
        salt     = secrets.token_bytes(32)      # 256-bit random salt
        peppered = password.encode("utf-8") + self._pepper
        dk       = hashlib.pbkdf2_hmac(
            "sha256", peppered, salt, self.ITERATIONS, dklen=32
        )
        return {
            "algo":       self.ALGO,
            "iterations": self.ITERATIONS,
            "salt_b64":   base64.b64encode(salt).decode(),
            "hash_b64":   base64.b64encode(dk).decode(),
        }

    def verify_password(self, password: str, stored_hash: dict) -> bool:
        """ตรวจสอบรหัสผ่านด้วย constant-time comparison"""
        salt     = base64.b64decode(stored_hash["salt_b64"])
        peppered = password.encode("utf-8") + self._pepper
        dk       = hashlib.pbkdf2_hmac(
            "sha256", peppered, salt, stored_hash["iterations"], dklen=32
        )
        expected = base64.b64decode(stored_hash["hash_b64"])
        return hmac.compare_digest(dk, expected)   # constant-time, no timing attack


# =============================================================================
# MODULE 4: Secure SQLite Database with HMAC Integrity
# =============================================================================

class SecureVotingDatabase:
    """
    SQLite database พร้อม:
    - ข้อมูล Voter ถูกเข้ารหัสด้วย AES-256-GCM ก่อนเก็บ
    - แต่ละ row มี HMAC-SHA256 สำหรับตรวจ Integrity
    - Tamper detection: ถ้าแก้ข้อมูลตรงๆ ใน DB ระบบจะตรวจพบ
    """

    def __init__(self, db_path: str, vault: AES256GCMVaultService,
                 hmac_key: bytes, pwd_service: PasswordHashingService):
        self.db_path     = db_path
        self.vault       = vault
        self.hmac_key    = hmac_key
        self.pwd_service = pwd_service
        self._init_db()

    def _init_db(self):
        con = sqlite3.connect(self.db_path)
        con.execute("""
            CREATE TABLE IF NOT EXISTS voters (
                voter_id       TEXT PRIMARY KEY,
                full_name_enc  TEXT NOT NULL,   -- AES-256-GCM encrypted JSON
                national_id_enc TEXT NOT NULL,  -- AES-256-GCM encrypted
                pwd_hash_json  TEXT NOT NULL,   -- salted hash JSON
                public_key_pem TEXT NOT NULL,   -- ECC public key
                has_voted      INTEGER DEFAULT 0,
                registered_at  TEXT NOT NULL,
                row_hmac       TEXT NOT NULL    -- HMAC of all fields
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS ballots (
                ballot_id      TEXT PRIMARY KEY,
                voter_id       TEXT NOT NULL,
                choice_enc     TEXT NOT NULL,   -- AES-256-GCM encrypted choice
                signature_b64  TEXT NOT NULL,   -- ECDSA signature
                timestamp      TEXT NOT NULL,
                row_hmac       TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                event     TEXT NOT NULL,
                detail    TEXT,
                ts        TEXT NOT NULL
            )
        """)
        con.commit()
        con.close()

    # --- HMAC helpers ---

    def _compute_row_hmac(self, fields: dict) -> str:
        """
        HMAC-SHA256 ของ canonical JSON ของ row fields
        ใช้ detect ถ้ามีการแก้ไขข้อมูลใน DB โดยตรง
        """
        canonical = json.dumps(fields, sort_keys=True, ensure_ascii=False)
        mac = hmac.new(self.hmac_key, canonical.encode("utf-8"), hashlib.sha256)
        return base64.b64encode(mac.digest()).decode()

    def _verify_row_hmac(self, fields: dict, stored_hmac: str) -> bool:
        expected = self._compute_row_hmac(fields)
        return hmac.compare_digest(expected, stored_hmac)

    # --- Voter Registration ---

    def register_voter(self, voter_id: str, full_name: str,
                       national_id: str, password: str,
                       public_key_pem: str) -> dict:
        """
        ลงทะเบียน Voter ใหม่:
        1. เข้ารหัส full_name และ national_id ด้วย AES-256-GCM
        2. Hash รหัสผ่านด้วย Salted SHA-256
        3. คำนวณ HMAC สำหรับ row
        4. INSERT ลง DB
        """
        full_name_enc  = json.dumps(
            self.vault.encrypt(full_name, associated_data=f"voter:{voter_id}:name"))
        national_id_enc = json.dumps(
            self.vault.encrypt(national_id, associated_data=f"voter:{voter_id}:nid"))
        pwd_hash_json  = json.dumps(self.pwd_service.hash_password(password))
        registered_at  = datetime.datetime.now(timezone.utc).isoformat() + "Z"

        hmac_fields = {
            "voter_id":       voter_id,
            "full_name_enc":  full_name_enc,
            "national_id_enc": national_id_enc,
            "pwd_hash_json":  pwd_hash_json,
            "public_key_pem": public_key_pem,
            "has_voted":      0,
            "registered_at":  registered_at,
        }
        row_hmac = self._compute_row_hmac(hmac_fields)

        con = sqlite3.connect(self.db_path)
        try:
            con.execute("""
                INSERT INTO voters
                (voter_id, full_name_enc, national_id_enc, pwd_hash_json,
                 public_key_pem, has_voted, registered_at, row_hmac)
                VALUES (?,?,?,?,?,?,?,?)
            """, (voter_id, full_name_enc, national_id_enc, pwd_hash_json,
                  public_key_pem, 0, registered_at, row_hmac))
            con.commit()
            self._audit(con, "REGISTER", f"voter_id={voter_id}")
            con.commit()
        finally:
            con.close()

        return {"status": "registered", "voter_id": voter_id,
                "registered_at": registered_at}

    # --- Ballot Submission ---

    def submit_ballot(self, voter_id: str, password: str,
                      choice: str, private_key: ec.EllipticCurvePrivateKey,
                      ecc_service: ECCVoterIdentityService) -> dict:
        """
        ยื่นบัตรโหวต:
        1. Authenticate voter (password verify)
        2. Check has_voted == 0 (ป้องกัน double voting)
        3. เข้ารหัส choice ด้วย AES-256-GCM
        4. Sign ballot payload ด้วย ECC private key
        5. บันทึก + อัพเดท has_voted = 1
        """
        con = sqlite3.connect(self.db_path)
        row = con.execute(
            "SELECT pwd_hash_json, public_key_pem, has_voted FROM voters WHERE voter_id=?",
            (voter_id,)
        ).fetchone()

        if not row:
            self._audit(con, "VOTE_FAIL", f"voter_id={voter_id} not found")
            con.commit(); con.close()
            return {"status": "error", "reason": "voter not found"}

        pwd_hash_json, public_key_pem, has_voted = row

        # 1. Verify password
        if not self.pwd_service.verify_password(password, json.loads(pwd_hash_json)):
            self._audit(con, "AUTH_FAIL", f"voter_id={voter_id} bad password")
            con.commit(); con.close()
            return {"status": "error", "reason": "authentication failed"}

        # 2. Check double voting
        if has_voted:
            self._audit(con, "DOUBLE_VOTE_ATTEMPT", f"voter_id={voter_id}")
            con.commit(); con.close()
            return {"status": "error", "reason": "already voted"}

        # 3. Encrypt choice
        choice_enc_dict = self.vault.encrypt(
            choice, associated_data=f"ballot:{voter_id}")
        choice_enc_json = json.dumps(choice_enc_dict)

        # 4. Build ballot payload & sign
        timestamp  = datetime.datetime.now(timezone.utc).isoformat() + "Z"
        ballot_id  = hashlib.sha256(
            f"{voter_id}:{timestamp}:{secrets.token_hex(8)}".encode()
        ).hexdigest()[:32]

        ballot_payload = {
            "ballot_id": ballot_id,
            "voter_id":  voter_id,
            "choice_enc_hash": hashlib.sha256(choice_enc_json.encode()).hexdigest(),
            "timestamp": timestamp,
        }
        signature_b64 = ECCVoterIdentityService.sign_ballot(private_key, ballot_payload)

        # 5. Verify signature using stored public key (sanity check)
        pub_key = ECCVoterIdentityService.deserialize_public_key(public_key_pem)
        if not ECCVoterIdentityService.verify_ballot_signature(
                pub_key, ballot_payload, signature_b64):
            self._audit(con, "SIG_VERIFY_FAIL", f"ballot_id={ballot_id}")
            con.commit(); con.close()
            return {"status": "error", "reason": "signature verification failed"}

        # 6. Compute row HMAC
        hmac_fields = {
            "ballot_id":     ballot_id,
            "voter_id":      voter_id,
            "choice_enc":    choice_enc_json,
            "signature_b64": signature_b64,
            "timestamp":     timestamp,
        }
        row_hmac = self._compute_row_hmac(hmac_fields)

        # 7. INSERT ballot + mark voter
        con.execute("""
            INSERT INTO ballots (ballot_id, voter_id, choice_enc, signature_b64, timestamp, row_hmac)
            VALUES (?,?,?,?,?,?)
        """, (ballot_id, voter_id, choice_enc_json, signature_b64, timestamp, row_hmac))

        # BUG FIX: must recompute voter row_hmac after has_voted changes to 1
        # (discovered during debug: audit reported 2 violations before tamper)
        voter_row = con.execute(
            "SELECT full_name_enc, national_id_enc, pwd_hash_json, "
            "public_key_pem, registered_at FROM voters WHERE voter_id=?",
            (voter_id,)
        ).fetchone()
        new_voter_hmac_fields = {
            "voter_id": voter_id,
            "full_name_enc":   voter_row[0],
            "national_id_enc": voter_row[1],
            "pwd_hash_json":   voter_row[2],
            "public_key_pem":  voter_row[3],
            "has_voted":       1,              # updated value
            "registered_at":   voter_row[4],
        }
        new_voter_hmac = self._compute_row_hmac(new_voter_hmac_fields)
        con.execute(
            "UPDATE voters SET has_voted=1, row_hmac=? WHERE voter_id=?",
            (new_voter_hmac, voter_id))
        self._audit(con, "VOTE_CAST", f"ballot_id={ballot_id} voter_id={voter_id}")
        con.commit()
        con.close()

        return {
            "status":       "ballot_accepted",
            "ballot_id":    ballot_id,
            "timestamp":    timestamp,
            "signature_ok": True,
        }

    # --- Integrity Audit ---

    def audit_integrity(self) -> dict:
        """
        ตรวจสอบ HMAC ของทุก row ในทุก table
        ถ้ามีการแก้ข้อมูลใน DB โดยตรงจะถูกตรวจพบที่นี่
        """
        con    = sqlite3.connect(self.db_path)
        report = {"voters": [], "ballots": [], "violations": []}

        # Check voters
        rows = con.execute(
            "SELECT voter_id, full_name_enc, national_id_enc, pwd_hash_json, "
            "public_key_pem, has_voted, registered_at, row_hmac FROM voters"
        ).fetchall()
        for r in rows:
            (vid, fn_enc, nid_enc, pwd_json,
             pk_pem, hv, reg_at, stored_mac) = r
            fields = {
                "voter_id": vid, "full_name_enc": fn_enc,
                "national_id_enc": nid_enc, "pwd_hash_json": pwd_json,
                "public_key_pem": pk_pem, "has_voted": hv,
                "registered_at": reg_at,
            }
            ok = self._verify_row_hmac(fields, stored_mac)
            entry = {"voter_id": vid, "hmac_ok": ok}
            report["voters"].append(entry)
            if not ok:
                report["violations"].append({"table": "voters", "id": vid})

        # Check ballots
        rows = con.execute(
            "SELECT ballot_id, voter_id, choice_enc, signature_b64, timestamp, row_hmac FROM ballots"
        ).fetchall()
        for r in rows:
            bid, vid, choice_enc, sig, ts, stored_mac = r
            fields = {
                "ballot_id": bid, "voter_id": vid,
                "choice_enc": choice_enc, "signature_b64": sig,
                "timestamp": ts,
            }
            ok = self._verify_row_hmac(fields, stored_mac)
            entry = {"ballot_id": bid, "voter_id": vid, "hmac_ok": ok}
            report["ballots"].append(entry)
            if not ok:
                report["violations"].append({"table": "ballots", "id": bid})

        con.close()
        report["integrity_status"] = (
            "PASS — No violations detected" if not report["violations"]
            else f"FAIL — {len(report['violations'])} violation(s) found"
        )
        return report

    from typing import Optional

    def decrypt_ballot_choice(self, ballot_id: str) -> Optional[str]:
        """ถอดรหัสทางเลือกจาก ballot (สำหรับการนับคะแนนที่ได้รับอนุญาต)"""
        con = sqlite3.connect(self.db_path)
        row = con.execute(
            "SELECT choice_enc, voter_id FROM ballots WHERE ballot_id=?",
            (ballot_id,)
        ).fetchone()
        con.close()
        if not row:
            return None
        choice_enc_json, voter_id = row
        enc_dict = json.loads(choice_enc_json)
        return self.vault.decrypt(enc_dict)

    def _audit(self, con: sqlite3.Connection, event: str, detail: str = ""):
        con.execute(
            "INSERT INTO audit_log (event, detail, ts) VALUES (?,?,?)",
            (event, detail, datetime.datetime.now(timezone.utc).isoformat() + "Z")
        )

    def get_audit_log(self) -> list[dict]:
        con  = sqlite3.connect(self.db_path)
        rows = con.execute(
            "SELECT log_id, event, detail, ts FROM audit_log ORDER BY log_id"
        ).fetchall()
        con.close()
        return [{"id": r[0], "event": r[1], "detail": r[2], "ts": r[3]} for r in rows]


# =============================================================================
# MODULE 5: Tamper Simulation (Phase 4 — Vulnerability Assessment)
# =============================================================================

class TamperSimulator:
    """
    จำลองการโจมตี Integrity โดยตรงที่ Database
    ใช้ใน Phase 4: Vulnerability Assessment
    """

    @staticmethod
    def simulate_direct_db_tamper(db_path: str, voter_id: str,
                                  field: str = "has_voted",
                                  new_value = 0) -> str:
        """
        แก้ไขค่าใน DB โดยตรง (bypass application layer)
        จะทำให้ HMAC ไม่ตรง → ตรวจพบใน audit_integrity()
        """
        con = sqlite3.connect(db_path)
        con.execute(
            f"UPDATE voters SET {field}=? WHERE voter_id=?",
            (new_value, voter_id)
        )
        con.commit()
        con.close()
        return f"[TAMPER_SIM] Set voters.{field}={new_value!r} for voter_id={voter_id!r}"


# =============================================================================
# DEMO — แสดงการทำงานทุก Module
# =============================================================================

def run_demo():
    print("=" * 65)
    print("  Blockchain Voting System — Cryptographic Demo")
    print(f"  Student: {STUDENT_NAME}  ID: {STUDENT_ID}")
    print("=" * 65)

    # --- 0. Key Factory (Student-ID Seeded) ---
    print("\n[0] Initializing Student-Seeded Key Factory...")
    kf = StudentSeededKeyFactory(STUDENT_ID, STUDENT_NAME)
    print(f"    Student Fingerprint : {kf.get_student_fingerprint()}")
    print(f"    AES Key (hex prefix): {kf.get_aes_key().hex()[:16]}...")
    print(f"    HMAC Key (hex prefix): {kf.get_hmac_key().hex()[:16]}...")

    # --- 1. AES-256-GCM ---
    print("\n[1] AES-256-GCM Encryption Test...")
    vault = AES256GCMVaultService(kf.get_aes_key())
    plaintext = f"สวัสดี ผม{STUDENT_NAME} รหัส {STUDENT_ID}"
    enc = vault.encrypt(plaintext, associated_data="demo:test")
    dec = vault.decrypt(enc)
    print(f"    Plaintext  : {plaintext}")
    print(f"    Ciphertext : {enc['ciphertext_b64'][:40]}...")
    print(f"    IV (nonce) : {enc['iv_b64']}")
    print(f"    Decrypted  : {dec}")
    print(f"    AES OK     : {plaintext == dec}")

    # --- 2. ECC Digital Signature ---
    print("\n[2] ECC Digital Signature (ECDSA P-256) Test...")
    ecc_svc    = ECCVoterIdentityService()
    priv, pub  = ECCVoterIdentityService.generate_keypair()
    ballot     = {"voter_id": "V001", "choice": "CandidateA",
                  "ts": "2025-09-01T09:00:00Z"}
    sig_b64    = ECCVoterIdentityService.sign_ballot(priv, ballot)
    valid      = ECCVoterIdentityService.verify_ballot_signature(pub, ballot, sig_b64)
    print(f"    Ballot payload : {ballot}")
    print(f"    Signature      : {sig_b64[:40]}...")
    print(f"    Verify (valid) : {valid}")
    # tampered ballot
    tampered   = dict(ballot, choice="CandidateB")
    tampered_v = ECCVoterIdentityService.verify_ballot_signature(pub, tampered, sig_b64)
    print(f"    Verify (tampered ballot): {tampered_v}  ← should be False")

    # --- 3. Password Hashing ---
    print("\n[3] SHA-256 Salting & Hashing Test...")
    pwd_svc  = PasswordHashingService(kf.get_password_global_pepper())
    password = "MySecureP@ss2025"
    hashed   = pwd_svc.hash_password(password)
    ok       = pwd_svc.verify_password(password, hashed)
    wrong    = pwd_svc.verify_password("WrongPassword", hashed)
    print(f"    Password   : {password}")
    print(f"    Hash       : {hashed['hash_b64'][:40]}...")
    print(f"    Salt       : {hashed['salt_b64'][:20]}...")
    print(f"    Iterations : {hashed['iterations']:,}")
    print(f"    Verify OK  : {ok}")
    print(f"    Wrong pwd  : {wrong}  ← should be False")

    # --- 4. Full Database Integration ---
    print("\n[4] Secure Database — Full Integration Test...")
    if Path(DB_PATH).exists():
        os.remove(DB_PATH)

    db = SecureVotingDatabase(
        DB_PATH, vault, kf.get_hmac_key(), pwd_svc
    )

    # Register voters
    priv1, pub1 = ECCVoterIdentityService.generate_keypair()
    priv2, pub2 = ECCVoterIdentityService.generate_keypair()
    reg1 = db.register_voter(
        voter_id="V001", full_name="นายสมชาย ใจดี",
        national_id="1234567890123", password="Voter1Pass!",
        public_key_pem=ECCVoterIdentityService.serialize_public_key(pub1)
    )
    reg2 = db.register_voter(
        voter_id="V002", full_name="นางสาวมาลี รักไทย",
        national_id="9876543210987", password="Voter2Pass!",
        public_key_pem=ECCVoterIdentityService.serialize_public_key(pub2)
    )
    print(f"    Registered V001: {reg1['status']} at {reg1['registered_at']}")
    print(f"    Registered V002: {reg2['status']}")

    # Submit ballots
    r1 = db.submit_ballot("V001", "Voter1Pass!", "พรรค A", priv1, ecc_svc)
    r2 = db.submit_ballot("V002", "Voter2Pass!", "พรรค B", priv2, ecc_svc)
    print(f"\n    V001 Vote: {r1['status']} | ballot_id={r1.get('ballot_id','N/A')[:16]}...")
    print(f"    V002 Vote: {r2['status']}")

    # Double vote attempt
    r_dbl = db.submit_ballot("V001", "Voter1Pass!", "พรรค B", priv1, ecc_svc)
    print(f"    V001 Double Vote: {r_dbl['status']} — reason: {r_dbl.get('reason')}")

    # --- 5. Integrity Check (clean) ---
    print("\n[5] Integrity Audit (before tamper)...")
    audit_clean = db.audit_integrity()
    print(f"    Status: {audit_clean['integrity_status']}")

    # --- 6. Tamper Simulation ---
    print("\n[6] Tamper Simulation — Direct DB Modification...")
    msg = TamperSimulator.simulate_direct_db_tamper(DB_PATH, "V001", "has_voted", 0)
    print(f"    {msg}")

    audit_tampered = db.audit_integrity()
    print(f"    Post-Tamper Audit: {audit_tampered['integrity_status']}")
    if audit_tampered["violations"]:
        for v in audit_tampered["violations"]:
            print(f"    ⚠ VIOLATION DETECTED: table={v['table']} id={v['id']}")

    # --- 7. Audit Log ---
    print("\n[7] Audit Log (last 5 entries)...")
    logs = db.get_audit_log()
    for entry in logs[-5:]:
        print(f"    [{entry['ts']}] {entry['event']:25s} | {entry['detail']}")

    # --- Summary ---
    print("\n" + "=" * 65)
    print("  CRYPTOGRAPHIC SUMMARY")
    print("=" * 65)
    print(f"  Student Fingerprint : {kf.get_student_fingerprint()}")
    print(f"  AES Algorithm       : AES-256-GCM (AEAD)")
    print(f"  ECC Curve           : NIST P-256 (secp256r1)")
    print(f"  Signature Algorithm : ECDSA with SHA-256")
    print(f"  Password Hashing    : PBKDF2-HMAC-SHA256 (100,000 iter)")
    print(f"  Integrity Check     : HMAC-SHA256 per row")
    print(f"  Tamper Detection    : {'ACTIVE ✓' if audit_tampered['violations'] else 'No violations'}")
    print(f"  DB Path             : {DB_PATH}")
    print("=" * 65)
    print(f"\n  ✓ All cryptographic modules initialized and verified.")
    print(f"  ✓ Student-seeded keys ensure unique ciphertext per student.")


if __name__ == "__main__":
    run_demo()