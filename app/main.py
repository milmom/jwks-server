from fastapi import FastAPI, Body, Request
from fastapi.responses import JSONResponse
import sqlite3
import uuid
import time
from argon2 import PasswordHasher

from .keys import KeyStore
from .jwt_service import issue_token

app = FastAPI()
KEYS = KeyStore.with_demo_keys()
ph = PasswordHasher()

request_times = []


@app.get("/.well-known/jwks.json")
def jwks():
    return {"keys": KEYS.get_unexpired_public_jwks()}


@app.post("/register")
def register(body: dict = Body(...)):
    password = str(uuid.uuid4())
    hashed = ph.hash(password)

    conn = sqlite3.connect("totally_not_my_privateKeys.db")
    c = conn.cursor()

    c.execute("INSERT INTO users (username,email,password_hash) VALUES (?,?,?)",
              (body["username"], body.get("email"), hashed))

    conn.commit()
    conn.close()

    return {"password": password}


@app.post("/auth")
def auth(request: Request, body: dict = Body(default={}), expired: str = None):
    # rate limiter
    now = time.time()
    request_times.append(now)
    request_times[:] = [t for t in request_times if now - t < 1]

    if len(request_times) > 10:
        return JSONResponse(status_code=429, content={"error": "Too many requests"})

    key = KEYS.get_best_signing_key(expired is not None)
    token, claims = issue_token(key, expired is not None)

    conn = sqlite3.connect("totally_not_my_privateKeys.db")
    c = conn.cursor()

    user_id = None
    if "username" in body:
        row = c.execute("SELECT id FROM users WHERE username=?", (body["username"],)).fetchone()
        if row:
            user_id = row[0]

    c.execute("INSERT INTO auth_logs (request_ip,user_id) VALUES (?,?)",
              (request.client.host, user_id))

    conn.commit()
    conn.close()

    return {"jwt": token}
