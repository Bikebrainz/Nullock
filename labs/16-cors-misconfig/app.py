"""
Lab 16 -- CORS misconfiguration (reflected origin + credentials).

/api/me reflects the request Origin straight into
Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials:
true -- so ANY website can read this authenticated response cross-origin
using the victim's cookies.

In Nullock:
    1. nullock scope add http://localhost:5016/*
    2. Send /api/me to Repeater with header:  Origin: https://evil.example
    3. The response echoes ACAO: https://evil.example + ACAC: true.
    4. Run the active probe (cors): it flags the reflected-credentialed
       origin (proving exploitability, not just "a CORS header exists").
    5. Confirm success: GET /flag with header Origin: https://evil.example
       -- same reflect-and-allow-credentials logic /api/me uses, hands
       back the flag once a genuinely cross-origin Origin gets reflected
       back with credentials allowed.

Fix: never reflect arbitrary Origins together with credentials. Use a
strict allow-list, and omit credentials for genuinely public data.
"""

import hashlib
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-16-cors-misconfig").hexdigest()[:16]


def cors_response(body):
    resp = jsonify(body)
    origin = request.headers.get("Origin", "*")
    # VULN: reflect any Origin AND allow credentials.
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/")
def index():
    return 'authenticated data at <a href="/api/me">/api/me</a>'


@app.route("/api/me")
def me():
    return cors_response({"user": "alice", "email": "alice@corp.example",
                           "role": "admin"})


@app.route("/flag")
def flag():
    origin = request.headers.get("Origin", "")
    own = urlparse(request.host_url).netloc
    # Solved only for a genuinely cross-origin Origin -- same-origin or
    # missing Origin proves nothing about the vuln.
    if not origin or urlparse(origin).netloc == own:
        return jsonify(solved=False, reason="send a cross-origin Origin header"), 400
    resp = cors_response({"user": "alice"})
    if (resp.headers.get("Access-Control-Allow-Origin") == origin and
            resp.headers.get("Access-Control-Allow-Credentials") == "true"):
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5016, debug=False)
