from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import rsa

from .models import KeyRecord


def _b64url_uint(n: int) -> str:
    """Base64url encode an unsigned integer (no padding), for JWK 'n' and 'e'."""
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
    """In-memory RSA keystore with expirations."""

    def __init__(self) -> None:
        self._keys: List[KeyRecord] = []

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)

    def add_rsa_key(self, expires_at: datetime) -> KeyRecord:
        kid = uuid.uuid4().hex
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = _public_jwk_from_private(kid, priv)
        record = KeyRecord(kid=kid, private_key=priv, public_jwk=jwk, expires_at=expires_at)
        self._keys.append(record)
        return record

    def get_unexpired_public_jwks(self, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
        now = now or self.now()
        return [kr.public_jwk for kr in self._keys if kr.expires_at > now]

    def get_best_signing_key(self, expired: bool, now: Optional[datetime] = None) -> KeyRecord:
        now = now or self.now()

        if not expired:
            candidates = [kr for kr in self._keys if kr.expires_at > now]
            if not candidates:
                raise ValueError("No unexpired keys available")
            return max(candidates, key=lambda kr: kr.expires_at)

        candidates = [kr for kr in self._keys if kr.expires_at <= now]
        if not candidates:
            raise ValueError("No expired keys available")
        return max(candidates, key=lambda kr: kr.expires_at)

    @classmethod
    def with_demo_keys(cls) -> "KeyStore":
        ks = cls()
        now = ks.now()
        ks.add_rsa_key(expires_at=now + timedelta(hours=1))   # valid key
        ks.add_rsa_key(expires_at=now - timedelta(hours=1))   # expired key
        return ks
