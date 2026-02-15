from __future__ import annotations

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

from .keys import KeyStore
from .jwt_service import issue_token

app = FastAPI(title="JWKS Server", version="1.0.0")

# In-memory keystore: 1 valid + 1 expired key
KEYS = KeyStore.with_demo_keys()


@app.get("/jwks")
def jwks():
    """Serve only non-expired public keys in JWKS format."""
    return {"keys": KEYS.get_unexpired_public_jwks()}


@app.post("/auth")
def auth(expired: bool = Query(default=False)):
    """
    Mock auth endpoint. POST with no body returns a signed JWT.

    If query param `expired` is present (e.g. /auth?expired=true),
    sign the JWT with an expired key and set an expired exp.
    """
    try:
        signing_key = KEYS.get_best_signing_key(expired=expired)
    except ValueError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

    token, claims = issue_token(signing_key=signing_key, expired=expired)
    return {"token": token, "claims": claims}
