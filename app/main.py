from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

from .keys import KeyStore
from .jwt_service import issue_token

app = FastAPI(title="JWKS Server", version="1.0.1")

# In-memory keystore: 1 valid + 1 expired key
KEYS = KeyStore.with_demo_keys()


@app.get("/jwks")
def jwks():
    """Serve only non-expired public keys in JWKS format."""
    return {"keys": KEYS.get_unexpired_public_jwks()}


# Safe compatibility alias (some clients expect this path)
@app.get("/.well-known/jwks.json")
def jwks_well_known():
    return {"keys": KEYS.get_unexpired_public_jwks()}


@app.post("/auth")
def auth(expired: Optional[str] = Query(default=None)):
    """
    Mock auth endpoint. POST with no body returns a signed JWT.

    IMPORTANT: The spec says "if the expired query parameter is present".
    So we treat *presence* of ?expired (with or without value) as True:
      - /auth              -> normal JWT
      - /auth?expired      -> expired JWT
      - /auth?expired=true -> expired JWT
    """
    use_expired = expired is not None

    try:
        signing_key = KEYS.get_best_signing_key(expired=use_expired)
    except ValueError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

    token, claims = issue_token(signing_key=signing_key, expired=use_expired)
    return {"token": token, "claims": claims}
