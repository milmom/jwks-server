from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Tuple

import jwt
from cryptography.hazmat.primitives import serialization

from .models import KeyRecord


def issue_token(signing_key: KeyRecord, expired: bool) -> Tuple[str, Dict[str, Any]]:
    """
    Returns (jwt_string, claims)

    - Always includes 'kid' in JWT header.
    - If expired=True, sets exp in the past (aligned to key expiry which is expired).
    - If expired=False, sets exp 15 minutes in the future.
    """
    now = datetime.now(timezone.utc)

    if expired:
        exp_dt = signing_key.expires_at  # already in the past for the expired key
    else:
        exp_dt = now + timedelta(minutes=15)

    claims: Dict[str, Any] = {
        "sub": "fake-user",
        "iat": int(now.timestamp()),
        "exp": int(exp_dt.timestamp()),
    }

    private_pem = signing_key.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(
        payload=claims,
        key=private_pem,
        algorithm="RS256",
        headers={"kid": signing_key.kid, "typ": "JWT"},
    )
    return token, claims
