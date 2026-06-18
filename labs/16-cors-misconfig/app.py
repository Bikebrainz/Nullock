"""
Lab 16 -- CORS misconfiguration (reflected origin + credentials).

/api/me reflects the request Origin straight into
Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials:
true -- so ANY website can read this authenticated response cross-origin
using the victim's cookies.

In Nullock:
    1. nullock scope ... add http://localhost:5016/*
    2. Send /api/me to Repeater with header:  Origin: https://evil.example
    3. The response echoes ACAO: https://evil.example + ACAC: true.
    4. Run the active probe (cors): it flags the reflected-credentialed
       origin (proving exploitability, not just "a CORS header exists").

Fix: never reflect arbitrary Origins together with credentials. Use a
strict allow-list, and omit credentials for genuinely public data.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/")
def index():
    return 'authenticated data at <a href="/api/me">/api/me</a>'


@app.route("/api/me")
def me():
    resp = jsonify({"user": "alice", "email": "alice@corp.example",
                    "role": "admin"})
    origin = request.headers.get("Origin", "*")
    # VULN: reflect any Origin AND allow credentials.
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5016, debug=False)
