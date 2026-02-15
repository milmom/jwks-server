from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict

import jwt
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * ((4 - len(seg) % 4) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _jwt_header(token: str) -> Dict[str, Any]:
    header_b64 = token.split(".")[0]
    return json.loads(_b64url_decode(header_b64))


def test_get_jwks_returns_keys_array():
    r = client.get("/jwks")
    assert r.status_code == 200
    body = r.json()
    assert "keys" in body
    assert isinstance(body["keys"], list)
    assert len(body["keys"]) >= 1


def test_post_auth_returns_token_and_claims():
    r = client.post("/auth")
    assert r.status_code == 200
    body = r.json()
    assert "token" in body and isinstance(body["token"], str)
    assert "claims" in body and isinstance(body["claims"], dict)
    assert "exp" in body["claims"]


def test_auth_token_kid_exists_in_jwks():
    token = client.post("/auth").json()["token"]
    hdr = _jwt_header(token)
    assert "kid" in hdr

    jwks = client.get("/jwks").json()["keys"]
    kids = {k["kid"] for k in jwks}
    assert hdr["kid"] in kids


def test_auth_expired_uses_expired_key_and_expired_exp():
    token = client.post("/auth?expired=true").json()["token"]
    hdr = _jwt_header(token)
    assert "kid" in hdr

    # JWKS serves only unexpired keys, so expired key's kid should not appear there
    jwks = client.get("/jwks").json()["keys"]
    kids = {k["kid"] for k in jwks}
    assert hdr["kid"] not in kids

    # exp should be in the past
    claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    assert claims["exp"] < int(time.time())
