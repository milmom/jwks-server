from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


@dataclass(frozen=True)
class KeyRecord:
    kid: str
    private_key: RSAPrivateKey
    public_jwk: Dict[str, Any]
    expires_at: datetime
