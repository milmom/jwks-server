from __future__ import annotations

import base64
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .models import KeyRecord

DB_FILE = "totally_not_my_privateKeys.db"


def _b64url_uint(n: int) -> str:
    if n == 0:
        raw = b"\x00"
    else:
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

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_file)

    def _init_db(self) -> None:
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """)
        conn.commit()
        conn.close()

    def _clear_keys(self) -> None:
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys")
        conn.commit()
        conn.close()

    def _generate_private_key(self) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def add_rsa_key(self, expires_at: datetime) -> KeyRecord:
        private_key = self._generate_private_key()

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        exp_ts = int(expires_at.timestamp())

        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem, exp_ts),
        )
        kid = cursor.lastrowid
        conn.commit()
        conn.close()

        kid_str = str(kid)
        jwk = _public_jwk_from_private(kid_str, private_key)

        return KeyRecord(
            kid=kid_str,
            private_key=private_key,
            public_jwk=jwk,
            expires_at=expires_at,
        )

    def _row_to_keyrecord(self, kid: int, pem: bytes, exp: int) -> KeyRecord:
        private_key = serialization.load_pem_private_key(pem, password=None)
        kid_str = str(kid)
        jwk = _public_jwk_from_private(kid_str, private_key)
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)

        return KeyRecord(
            kid=kid_str,
            private_key=private_key,
            public_jwk=jwk,
            expires_at=expires_at,
        )

    def get_unexpired_public_jwks(self, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
        now = now or self.now()
        now_ts = int(now.timestamp())

        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC",
            (now_ts,),
        )
        rows = cursor.fetchall()
        conn.close()

        jwks: List[Dict[str, Any]] = []
        for kid, pem, exp in rows:
            record = self._row_to_keyrecord(kid, pem, exp)
            jwks.append(record.public_jwk)

        return jwks

    def get_best_signing_key(self, expired: bool, now: Optional[datetime] = None) -> KeyRecord:
        now = now or self.now()
        now_ts = int(now.timestamp())

        conn = self._connect()
        cursor = conn.cursor()

        if expired:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                (now_ts,),
            )
        else:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                (now_ts,),
            )

        row = cursor.fetchone()
        conn.close()

        if row is None:
            if expired:
                raise ValueError("No expired keys available")
            raise ValueError("No unexpired keys available")

        kid, pem, exp = row
        return self._row_to_keyrecord(kid, pem, exp)

    @classmethod
    def with_demo_keys(cls, db_file: str = DB_FILE) -> "KeyStore":
        ks = cls(db_file=db_file)
        now = ks.now()
        ks.add_rsa_key(expires_at=now + timedelta(hours=1))
        ks.add_rsa_key(expires_at=now - timedelta(hours=1))
        return ks
