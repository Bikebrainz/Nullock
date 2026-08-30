"""
Lab 71 -- JWT `x5u` header injection (X.509 certificate URL spoofing).

/login issues an RS256 JWT whose header carries an `x5u` claim -- the URL of
an X.509 certificate the verifier should extract the signing key from. This
is RFC 7515's OTHER key-location header (alongside `jku`): instead of a raw
JWK, `x5u` points at a PEM/DER certificate, and the verifier's job is to
pull the public key out of it. The spec is explicit that this is only safe
if the certificate chain is validated against a trusted CA before its key
is trusted for anything -- otherwise `x5u` is just "fetch a key from
wherever this token says, and believe it." This verifier does exactly that:
it fetches whatever cert the token's `x5u` names, extracts the public key,
and never once checks who signed the certificate. A self-signed cert an
attacker mints in one line of `cryptography` code parses just as cleanly as
this server's own, and gets trusted just the same.

Distinct from every other JWT lab here: 51 is RS256/HS256 algorithm
confusion (same key, wrong algorithm), 53 is `kid` path traversal (existing
key, wrong file on disk), 68 is `jku` pointing at an attacker's raw JWK
JSON. This one never touches a JWK at all -- the attacker publishes a
CERTIFICATE (X.509, the same structure TLS uses), and the bug isn't merely
"no allow-list on the URL" (68's bug) but "no chain-of-trust check on what
comes back", which is the specific failure mode `x5u` implementations are
warned about and this one ignores completely.

Nullock's automated `nullock jwt test` has no x5u coverage at all -- its
built-in forgery families are alg:none, empty/weak HMAC secrets, and `kid`
injection (see labs 03/51/53/68's notes); x5u parsing a fetched certificate
is outside all of them, so this is a hand-with-Repeater-plus-a-forge lab
like 68, not something the active prober can stumble into.

In Nullock:
    1. nullock scope add http://localhost:5071/*
    2. GET /login -- an RS256 token, header "x5u" points at this server's
       own /certs/server (a real, self-signed cert this app generated at
       startup). GET /admin with it: 403 (role is "user").
    3. Generate your own RSA keypair AND a self-signed X.509 certificate for
       it locally (`cryptography`'s x509.CertificateBuilder, or `openssl req
       -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem`). POST the
       certificate's PEM text as the raw body to this app's stand-in for
       "an attacker-controlled host": POST /attacker/publish/evil. It's now
       servable at GET /attacker/certs/evil.
    4. Forge a token with your PRIVATE key: header {"alg":"RS256",
       "x5u":"http://127.0.0.1:5071/attacker/certs/evil"}, payload
       {"role":"admin","sub":"mallory","exp":<future>}. Send it as
       `Authorization: Bearer <forged>` to GET /admin.
    5. The server fetches YOUR x5u URL, parses the PEM as an X.509
       certificate (it IS one -- your own, self-signed, but structurally
       valid), pulls out the public key inside it, and verifies your
       token's RS256 signature against that key -- which checks out,
       because you hold the matching private key. Nobody ever asked who
       (if anyone) signed the certificate itself. 200, welcome admin.
    6. Confirm success: GET /flag with the same forged token.

Fix: never resolve a signing key from a URL the token itself supplies.
If `x5u` must be supported, validate the fetched certificate's full chain
against a fixed, pre-configured trusted CA bundle before trusting its key
for anything -- a syntactically valid certificate proves nothing about who
it belongs to.

(Needs `requests`, `pyjwt`, `cryptography` -- the labs' non-Flask deps.)
"""

import datetime
import hashlib
import time

from flask import Flask, request, jsonify
import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-71-jwt-x5u-injection").hexdigest()[:16]


def _self_signed_cert(priv, common_name):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(priv, hashes.SHA256())
    )


_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_priv_pem = _priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_server_cert_pem = _self_signed_cert(_priv, "nullock-lab71.internal").public_bytes(
    serialization.Encoding.PEM
)

# Attacker-published certificates, keyed by label -- stands in for "a
# certificate hosted on infrastructure the attacker controls".
ATTACKER_CERTS = {}


@app.route("/certs/server")
def server_cert():
    return _server_cert_pem, 200, {"Content-Type": "application/x-pem-file"}


@app.route("/login")
def login():
    payload = {"role": "user", "sub": "alice", "exp": int(time.time()) + 3600}
    token = jwt.encode(payload, _priv_pem, algorithm="RS256",
                        headers={"x5u": request.host_url + "certs/server"})
    return jsonify(token=token)


@app.route("/attacker/publish/<label>", methods=["POST"])
def attacker_publish(label):
    ATTACKER_CERTS[label] = request.get_data(as_text=True)
    return jsonify(published=label)


@app.route("/attacker/certs/<label>")
def attacker_certs(label):
    pem = ATTACKER_CERTS.get(label)
    if pem is None:
        return "not found", 404
    return pem, 200, {"Content-Type": "application/x-pem-file"}


def _verify(auth):
    if not auth.startswith("Bearer "):
        return None
    token = auth.removeprefix("Bearer ")
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return None
    x5u = header.get("x5u")
    if not x5u:
        return None
    try:
        # VULN: fetches a certificate from a URL the TOKEN ITSELF names, then
        # trusts whatever public key is inside it -- no chain-of-trust check
        # against any CA, no pinning to this server's own certificate.
        cert_pem = requests.get(x5u, timeout=3).content
        cert = x509.load_pem_x509_certificate(cert_pem)
        pub_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
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
    app.run(host="127.0.0.1", port=5071, debug=False)
