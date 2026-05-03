from __future__ import annotations

import base64
import sqlite3
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import KeyRecord

DB_FILE = "totally_not_my_privateKeys.db"

AES_KEY = os.getenv("NOT_MY_KEY")
if AES_KEY is None:
    raise RuntimeError("NOT_MY_KEY not set")
AES_KEY = AES_KEY.encode().ljust(32, b'\0')[:32]


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _public_jwk_from_private(kid: str, private_key: rsa.RSAPrivateKey) -> Dict[str, Any]:
    pub = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64url_uint(pub.n),
        "e": _b64url_uint(pub.e),
    }


class KeyStore:
    def __init__(self, db_file: str = DB_FILE) -> None:
        self.db_file = db_file
        self._init_db()
        self._clear_keys()

    def _connect(self):
        return sqlite3.connect(self.db_file)

    def _init_db(self):
        conn = self._connect()
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            email TEXT,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER
        )
        """)

        conn.commit()
        conn.close()

    def _clear_keys(self):
        conn = self._connect()
        conn.execute("DELETE FROM keys")
        conn.commit()
        conn.close()

    def _generate_private_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def add_rsa_key(self, expires_at: datetime):
        private_key = self._generate_private_key()

        raw_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        aesgcm = AESGCM(AES_KEY)
        nonce = os.urandom(12)
        encrypted = nonce + aesgcm.encrypt(nonce, raw_pem, None)

        conn = self._connect()
        c = conn.cursor()
        c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
                  (encrypted, int(expires_at.timestamp())))
        kid = c.lastrowid
        conn.commit()
        conn.close()

        return self._row_to_keyrecord(kid, encrypted, int(expires_at.timestamp()))

    def _row_to_keyrecord(self, kid, pem, exp):
        aesgcm = AESGCM(AES_KEY)
        nonce = pem[:12]
        decrypted = aesgcm.decrypt(nonce, pem[12:], None)

        private_key = serialization.load_pem_private_key(decrypted, password=None)

        return KeyRecord(
            kid=str(kid),
            private_key=private_key,
            public_jwk=_public_jwk_from_private(str(kid), private_key),
            expires_at=datetime.fromtimestamp(exp, tz=timezone.utc),
        )

    def get_unexpired_public_jwks(self):
        now = int(datetime.now(timezone.utc).timestamp())

        conn = self._connect()
        rows = conn.execute("SELECT kid,key,exp FROM keys WHERE exp>?", (now,)).fetchall()
        conn.close()

        return [self._row_to_keyrecord(*r).public_jwk for r in rows]

    def get_best_signing_key(self, expired: bool):
        now = int(datetime.now(timezone.utc).timestamp())

        conn = self._connect()
        if expired:
            row = conn.execute("SELECT kid,key,exp FROM keys WHERE exp<=? LIMIT 1", (now,)).fetchone()
        else:
            row = conn.execute("SELECT kid,key,exp FROM keys WHERE exp>? LIMIT 1", (now,)).fetchone()
        conn.close()

        return self._row_to_keyrecord(*row)

    @classmethod
    def with_demo_keys(cls):
        ks = cls()
        now = datetime.now(timezone.utc)
        ks.add_rsa_key(now + timedelta(hours=1))
        ks.add_rsa_key(now - timedelta(hours=1))
        return ks
