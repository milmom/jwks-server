from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.keys import KeyStore


def test_jwks_filters_expired_keys():
    ks = KeyStore()
    now = datetime.now(timezone.utc)

    ks.add_rsa_key(expires_at=now + timedelta(minutes=5))
    ks.add_rsa_key(expires_at=now - timedelta(minutes=5))

    jwks = ks.get_unexpired_public_jwks(now=now)
    assert len(jwks) == 1
    assert jwks[0]["kty"] == "RSA"
    assert "kid" in jwks[0]
    assert "n" in jwks[0]
    assert "e" in jwks[0]


def test_get_best_signing_key_unexpired():
    ks = KeyStore()
    now = datetime.now(timezone.utc)

    ks.add_rsa_key(expires_at=now + timedelta(minutes=1))
    k2 = ks.add_rsa_key(expires_at=now + timedelta(minutes=10))
    best = ks.get_best_signing_key(expired=False, now=now)
    assert best.kid == k2.kid


def test_get_best_signing_key_expired():
    ks = KeyStore()
    now = datetime.now(timezone.utc)

    ks.add_rsa_key(expires_at=now - timedelta(minutes=10))
    k2 = ks.add_rsa_key(expires_at=now - timedelta(minutes=1))
    best = ks.get_best_signing_key(expired=True, now=now)
    assert best.kid == k2.kid


def test_get_best_signing_key_raises_when_missing():
    ks = KeyStore()
    now = datetime.now(timezone.utc)

    with pytest.raises(ValueError):
        ks.get_best_signing_key(expired=False, now=now)

    with pytest.raises(ValueError):
        ks.get_best_signing_key(expired=True, now=now)
