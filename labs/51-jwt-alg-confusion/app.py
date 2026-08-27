"""
Lab 51 -- JWT algorithm confusion (RS256 -> HS256).

The API signs tokens with RS256 and publishes the RSA PUBLIC key at
/pubkey, as any real RS256 API must. The verifier trusts the token's own
`alg` header to pick a path: RS256 checks against the public key as
normal, but an HS256 token is "verified" by HMAC-SHA256 over that same
public key's PEM bytes. Anyone who fetched /pubkey can forge an HS256
token with a signature the server will accept.

Run:
    pip install flask pyjwt cryptography
    python app.py

In Nullock:
    1. nullock scope add http://localhost:5051/*
    2. GET /login -- a JWT (role=user, RS256-signed). GET /pubkey -- the
       RSA public key PEM the server verifies against.
    3. POST /api/jwt/forge {"token": <the RS256 token>, "attack": "hs256",
       "secret": <the /pubkey PEM text, verbatim>, "claims": {"role":
       "admin"}} -- the forge endpoint's own doc names this exact move:
       "hs256 -> re-sign with `secret` (also the RS256->HS256 confusion
       primitive: pass the server's PEM public key as secret)". (Or by
       hand: header {"alg":"HS256"}, signature = HMAC-SHA256(header + "."
       + payload, pubkey_pem).)
    4. GET /admin with Authorization: Bearer <forged token> -- 200.
    5. Confirm success: GET /flag with the same header -- hands back the
       flag once role=="admin" checks out against a token nobody with
       only the public key could legitimately produce.
    6. `nullock jwt test http://localhost:5051/flag <token>` runs this
       exact confusion attack (plus alg:none and weak-HMAC-secret) and
       confirms acceptance automatically.

Fix: pin one expected algorithm (`algorithms=["RS256"]` only) server-side
-- never let the token's own alg header pick the verification key.
"""

import base64, hashlib, hmac, json, time
from flask import Flask, request, jsonify
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-51-jwt-alg-confusion").hexdigest()[:16]

_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
PUBLIC_PEM = _private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


@app.route("/login")
def login():
    payload = {"role": "user", "sub": "alice", "exp": int(time.time()) + 3600}
    token = jwt.encode(payload, PRIVATE_PEM, algorithm="RS256")
    return jsonify(token=token)


@app.route("/pubkey")
def pubkey():
    return PUBLIC_PEM, 200, {"Content-Type": "text/plain"}


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify(auth):
    if not auth.startswith("Bearer "):
        return None
    token = auth.removeprefix("Bearer ")
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return None
    if header.get("alg") == "RS256":
        try:
            return jwt.decode(token, PUBLIC_PEM, algorithms=["RS256"])
        except Exception:
            return None
    if header.get("alg") == "HS256":
        # VULN: verifies HS256 tokens by HMAC-SHA256 over the RSA PUBLIC
        # key bytes -- anyone who fetched /pubkey can forge one. PyJWT's
        # own decode() refuses a PEM as an HMAC secret, so this reimplements
        # the check by hand to bypass that guard, same as real-world bugs.
        signing_input, sig_b64 = token.rsplit(".", 1)
        expected = hmac.new(PUBLIC_PEM, signing_input.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
            return None
        _, payload_b64 = signing_input.split(".")
        return json.loads(_b64url_decode(payload_b64))
    return None


@app.route("/admin")
def admin():
    payload = _verify(request.headers.get("Authorization", ""))
    if payload is None:
        return "bad token", 401
    if payload.get("role") != "admin":
        return "forbidden", 403
    return "welcome, admin"


@app.route("/flag")
def flag():
    payload = _verify(request.headers.get("Authorization", ""))
    if payload is None or payload.get("role") != "admin":
        return jsonify(solved=False), 403
    return jsonify(solved=True, flag=FLAG)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5051, debug=False)
