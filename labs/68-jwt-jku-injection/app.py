"""
Lab 68 -- JWT `jku` header injection (JWKS URL spoofing).

/login issues an RS256 JWT whose header carries a `jku` claim -- the URL of
the JSON Web Key Set the verifier should fetch the signing key from. Real
JWT libraries support this so one issuer can rotate keys or federate across
hosts without redeploying every verifier. The bug: the verifier trusts
whatever URL the TOKEN ITSELF names in `jku`, with no allow-list pinning it
to this server's own /jwks. Publish your own key set anywhere reachable,
point a self-signed token's `jku` at it, and the server fetches YOUR key and
validates the forgery against it.

This is a different JWT primitive from the other JWT labs here: Lab 51 is
RS256/HS256 confusion (same key, wrong algorithm), Lab 53 is `kid` path
traversal (existing key, wrong file). This one never touches the server's
real key at all -- the attacker supplies an entirely new one and the server
fetches it because the token said to.

In Nullock:
    1. nullock scope add http://localhost:5068/*
    2. GET /login -- an RS256 token, header includes "kid":"prod-2026" and
       "jku":"http://127.0.0.1:5068/jwks" (the server's real key set).
       GET /admin with it: 403 (role is "user"). Note there's no
       automated `nullock jwt test` coverage for jku forgery yet (its
       wordlist targets alg:none and weak/empty HMAC secrets) -- confirm
       this one with Repeater plus a short local forge, same as any real
       jku pentest needs a scripted forgery step.
    3. Generate your own RSA keypair locally (openssl, or `cryptography` in
       a REPL) and publish its PUBLIC JWK to this app's stand-in for "an
       attacker-controlled host": POST /attacker/publish/evil with body
       {"kty":"RSA","kid":"evil","n":"<b64url modulus>","e":"<b64url
       exponent>"}. It's now servable at GET /attacker/keys/evil.
    4. Forge a token with your PRIVATE key: header {"alg":"RS256",
       "kid":"evil","jku":"http://127.0.0.1:5068/attacker/keys/evil"},
       payload {"role":"admin","sub":"mallory","exp":<future>}. In Repeater,
       send it as `Authorization: Bearer <forged>` to GET /admin.
    5. The server fetches YOUR jku URL (no allow-list -- any host, including
       this one under a path you control, is accepted), finds `kid:"evil"`
       in the key set you published, and verifies the RS256 signature
       against YOUR public key -- which of course checks out, because you
       hold the matching private key. 200, welcome admin.
    6. Confirm success: GET /flag with the same forged token.

Fix: never resolve a signing key from a URL the token itself supplies.
Pin verification to a fixed, pre-configured JWKS URL (or a local key store)
and ignore `jku` entirely; if key rotation via URL is required, allow-list
the exact trusted hosts and never fetch on unauthenticated input.

(Needs `requests`, `pyjwt`, `cryptography` -- the labs' non-Flask deps.)
"""

import base64
import hashlib
import time
from flask import Flask, request, jsonify
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-68-jwt-jku-injection").hexdigest()[:16]

SERVER_KID = "prod-2026"
_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_priv_pem = _priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_pub_numbers = _priv.public_key().public_numbers()

# Attacker-published key sets, keyed by label -- stands in for "a JWKS
# document hosted on infrastructure the attacker controls".
ATTACKER_KEYS = {}


def _b64url_uint(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_uint_decode(s):
    pad = "=" * (-len(s) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(s + pad), "big")


@app.route("/jwks")
def jwks():
    return jsonify(keys=[{"kty": "RSA", "kid": SERVER_KID, "use": "sig",
                           "alg": "RS256", "n": _b64url_uint(_pub_numbers.n),
                           "e": _b64url_uint(_pub_numbers.e)}])


@app.route("/login")
def login():
    payload = {"role": "user", "sub": "alice", "exp": int(time.time()) + 3600}
    token = jwt.encode(payload, _priv_pem, algorithm="RS256",
                        headers={"kid": SERVER_KID, "jku": request.host_url + "jwks"})
    return jsonify(token=token)


@app.route("/attacker/publish/<label>", methods=["POST"])
def attacker_publish(label):
    ATTACKER_KEYS[label] = request.get_json(force=True, silent=True) or {}
    return jsonify(published=label)


@app.route("/attacker/keys/<label>")
def attacker_keys(label):
    jwk = ATTACKER_KEYS.get(label)
    if jwk is None:
        return "not found", 404
    return jsonify(keys=[jwk])


def _verify(auth):
    if not auth.startswith("Bearer "):
        return None
    token = auth.removeprefix("Bearer ")
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return None
    jku, kid = header.get("jku"), header.get("kid")
    if not jku or not kid:
        return None
    try:
        # VULN: fetches the key set from a URL the TOKEN ITSELF names,
        # instead of a fixed, pre-configured trusted JWKS endpoint.
        keys = requests.get(jku, timeout=3).json().get("keys", [])
    except Exception:
        return None
    jwk = next((k for k in keys if k.get("kid") == kid), None)
    if jwk is None:
        return None
    try:
        pub = rsa.RSAPublicNumbers(_b64url_uint_decode(jwk["e"]),
                                    _b64url_uint_decode(jwk["n"])).public_key()
        pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return jwt.decode(token, pub_pem, algorithms=["RS256"])
    except Exception:
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
    app.run(host="127.0.0.1", port=5068, debug=False)
