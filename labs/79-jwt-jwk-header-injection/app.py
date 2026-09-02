"""
Lab 79 -- JWT `jwk` header injection (embedded public key, no fetch needed).

/login issues an RS256 JWT signed with this server's real key. The
verifier resolves the key to check a token against by looking first for a
`jwk` header parameter (RFC 7515 4.1.3: the signing key itself, embedded
directly in the token's own unprotected header as a JSON Web Key) and only
falls back to its own fixed keystore when `jwk` is absent. It never checks
that an embedded `jwk` is one THIS SERVER issued or trusts -- so an
attacker can mint a brand-new RSA keypair, embed the PUBLIC half directly
in a forged token's header, sign that token with the matching PRIVATE
half, and the verifier happily validates the signature against the very
key the attacker just handed it. No server-side trust store is ever
consulted for the embedded case.

This is the third member of the "verifier trusts a key the token names"
JWT family here, and the one that needs no network step at all: Lab 68's
`jku` points the verifier at a URL it must FETCH a key set from (an SSRF-
adjacent primitive -- the forgery only completes once that fetch succeeds
against attacker infrastructure); Lab 71's `x5u` is the same fetch-a-
remote-resource shape one level removed, pointing at an X.509 cert instead
of a raw JWK. `jwk` skips the round trip entirely -- RFC 7515 designed it
so the key travels WITH the token, which is exactly why trusting it
unconditionally is worse in one respect: there's no attacker-controlled
URL for a network-level control (an egress allow-list, DNS logging, an
OAST callback) to ever observe. Nullock's `/api/jwt/analyze` (jwt_tool.cpp)
already flags `alg:none`, absent-alg, symmetric-vs-asymmetric algorithm
confusion, and risky `kid` values (path traversal / injection metachars) --
but has no check for an embedded `jwk` header parameter at all, so this
verifier's specific hole surfaces only by reading the header of a real
token and noticing the extra field.

In Nullock:
    1. nullock scope add http://localhost:5079/*
    2. GET /login -- an RS256 token, header {"alg":"RS256","kid":"prod-2026"}
       (no jwk). GET /admin with it: 403 (role is "user"). Paste it into
       Inspector's JWT TOOLKIT -- ANALYZE lists the asymmetric-algorithm
       info finding but nothing else stands out; the real hole is what the
       verifier does when a header field ANALYZE never sees added.
    3. Generate your own RSA keypair locally (openssl, or `cryptography` in
       a REPL -- the walkthrough's forge.py does this for you).
    4. Forge a token with your PRIVATE key, and embed its PUBLIC half
       directly in the header as `jwk`: header
       {"alg":"RS256","kid":"evil","jwk":{"kty":"RSA","n":"<b64url
       modulus>","e":"<b64url exponent>"}}, payload
       {"role":"admin","sub":"mallory","exp":<future>}.
    5. Send it as `Authorization: Bearer <forged>` to GET /admin in
       Repeater. The verifier sees the `jwk` field, builds a public key
       straight from it -- no lookup, no trust-store check, no comparison
       against the real `kid:"prod-2026"` key at all -- and verifies your
       own signature against your own embedded key. Of course it checks
       out. 200, welcome admin.
    6. Confirm success: GET /flag with the same forged token.

Fix: never build a verification key from a `jwk` (or `jwks`) header
parameter the token itself supplies. Resolve signing keys ONLY from a
fixed, pre-configured server-side keystore looked up by `kid`; treat any
inbound `jwk`/`jku`/`x5u` header field as attacker input to be ignored,
not a hint about where to find the key.

(Needs `pyjwt`, `cryptography` -- the labs' non-Flask deps.)
"""

import base64
import hashlib
import time
from flask import Flask, request, jsonify
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-79-jwt-jwk-header-injection").hexdigest()[:16]

SERVER_KID = "prod-2026"
_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_priv_pem = _priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_pub_numbers = _priv.public_key().public_numbers()


def _b64url_uint(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_uint_decode(s):
    pad = "=" * (-len(s) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(s + pad), "big")


@app.route("/")
def index():
    return '<a href="/login">log in</a>'


@app.route("/login")
def login():
    payload = {"role": "user", "sub": "alice", "exp": int(time.time()) + 3600}
    token = jwt.encode(payload, _priv_pem, algorithm="RS256",
                        headers={"kid": SERVER_KID})
    return jsonify(token=token)


def _verify(auth):
    if not auth.startswith("Bearer "):
        return None
    token = auth.removeprefix("Bearer ")
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return None
    embedded = header.get("jwk")
    try:
        if embedded is not None:
            # VULN: builds the verification key straight from a JWK the
            # TOKEN ITSELF carries in its own header, instead of only ever
            # resolving keys from the server's fixed keystore below.
            pub = rsa.RSAPublicNumbers(
                _b64url_uint_decode(embedded["e"]),
                _b64url_uint_decode(embedded["n"]),
            ).public_key()
            pub_pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            return jwt.decode(token, pub_pem, algorithms=["RS256"])
        if header.get("kid") != SERVER_KID:
            return None
        pub_pem = _priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
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
    app.run(host="127.0.0.1", port=5079, debug=False)
