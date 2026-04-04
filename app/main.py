from __future__ import annotations

from typing import Optional

from fastapi import Body, FastAPI, Query
from fastapi.responses import JSONResponse

from .jwt_service import issue_token
from .keys import KeyStore

app = FastAPI(title="JWKS Server", version="2.0.0")

KEYS = KeyStore.with_demo_keys()


@app.get("/jwks")
def jwks():
    return {"keys": KEYS.get_unexpired_public_jwks()}


@app.get("/.well-known/jwks.json")
def jwks_well_known():
    return {"keys": KEYS.get_unexpired_public_jwks()}


@app.post("/auth")
def auth(
    expired: Optional[str] = Query(default=None),
    body: Optional[dict] = Body(default=None)
):
    use_expired = expired is not None

    try:
        signing_key = KEYS.get_best_signing_key(expired=use_expired)
    except ValueError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

    token, claims = issue_token(signing_key=signing_key, expired=use_expired)
    return {"jwt": token, "token": token, "claims": claims}
