"""
Lab 53 -- JWT `kid` header injection (path traversal -> empty-key forgery).

The API signs session tokens with HMAC and names which on-disk key file to
verify against via the JWT header's own `kid` field -- a real pattern for
services that rotate or multi-tenant their signing keys. The verifier joins
`kid` onto a fixed keys/ directory with no traversal check, so a `kid` that
escapes that directory can point the HMAC lookup at /dev/null, a file
guaranteed to be empty -- sign a token with an empty key and the server
accepts it. A single non-recursive `kid.replace("../", "")` filter blocks
the obvious repeated "../../.../dev/null" attempt (it strips clean down to
a harmless "dev/null"), but doesn't stop a doubled-dot kid or a bare
absolute path from getting there anyway.

Run:
    pip install flask

In Nullock:
    1. nullock scope add http://localhost:5053/*
    2. GET /login -- an HS256 JWT with kid="hmac.key", signed with a real
       secret generated fresh at startup. GET /account with it -- 200,
       role=user.
    3. Forge a token: header {"alg":"HS256","kid":"/dev/null"}, payload
       {"role":"admin", "sub":"alice"}, HMAC-signed with an EMPTY key.
       Send it to /account -- 200, role=admin: os.path.join(KEYS_DIR,
       "/dev/null") returns "/dev/null" outright, since an absolute second
       argument overrides the base entirely -- the "safe" keys/ fence
       never even applies.
    4. Same idea, blocked-then-bypassed: kid="../../../../../../../../../../dev/null"
       gets 401 (the filter strips every "../" down to "dev/null", a file
       that doesn't exist inside keys/) but kid made of twenty "....//"
       segments followed by "dev/null" gets 200 -- one non-recursive
       `.replace("../", "")` pass only removes what it sees on the first
       scan, and the doubled dots leave behind twenty fresh, unscanned
       "../" runs that walk past the filesystem root and back down to the
       null device.
    5. `nullock jwt test http://localhost:5053/account <the /login token>`
       finds this on its own -- the kid-injection probe tries exactly this
       traversal family (plain /dev/null, repeated and doubled "../"),
       differentially, across every HS alg.
    6. Confirm success: GET /flag with the forged admin token.

Fix: never let request-controlled input choose a filesystem path for a
signing key. Look keys up by an opaque id against a fixed allow-list /
in-memory table instead of joining a raw filename onto a directory, and
reject any `kid` that isn't in that table before it ever reaches a
filesystem call.
"""

import hashlib
import hmac
import json
import os
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-53-jwt-kid-injection").hexdigest()[:16]

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
REAL_KEY_NAME = "hmac.key"


def _b64url(data):
    return urlsafe_b64encode(data).rstrip(b"=")


def _b64url_decode(s):
    return urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(header, payload, key):
    signing_input = _b64url(json.dumps(header).encode()) + b"." + _b64url(json.dumps(payload).encode())
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64url(sig)).decode()


def _resolve_key(kid):
    # VULN: one non-recursive strip of the literal "../" substring, then a
    # raw os.path.join -- an absolute kid drops KEYS_DIR entirely, and a
    # doubled-dot kid reassembles a traversal the filter already "cleared".
    safe = kid.replace("../", "")
    path = os.path.join(KEYS_DIR, safe)
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _verify(token):
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None
    if header.get("alg") != "HS256":
        return None
    key = _resolve_key(header.get("kid", REAL_KEY_NAME))
    if key is None:
        return None
    signing_input = (header_b64 + "." + payload_b64).encode()
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
        return None
    return payload


@app.route("/login")
def login():
    with open(os.path.join(KEYS_DIR, REAL_KEY_NAME), "rb") as fh:
        real_key = fh.read()
    header = {"alg": "HS256", "typ": "JWT", "kid": REAL_KEY_NAME}
    payload = {"role": "user", "sub": "alice", "exp": int(time.time()) + 3600}
    return jsonify(token=_sign(header, payload, real_key))


@app.route("/account")
def account():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return "missing token", 401
    payload = _verify(auth.removeprefix("Bearer "))
    if payload is None:
        return "bad token", 401
    return jsonify(role=payload.get("role"), sub=payload.get("sub"))


@app.route("/flag")
def flag():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify(solved=False), 401
    payload = _verify(auth.removeprefix("Bearer "))
    if payload is None or payload.get("role") != "admin":
        return jsonify(solved=False), 403
    return jsonify(solved=True, flag=FLAG)


if __name__ == "__main__":
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(os.path.join(KEYS_DIR, REAL_KEY_NAME), "wb") as fh:
        fh.write(os.urandom(32))
    app.run(host="127.0.0.1", port=5053, debug=False)
