"""
Lab 30 -- Rate-limit bypass via X-Forwarded-For.

/login rate-limits by client IP, but it trusts the X-Forwarded-For header
to decide that IP -- so an attacker rotates X-Forwarded-For to reset the
counter and brute-force the password freely.

In Nullock:
    1. nullock scope add http://localhost:5030/*
    2. POST /login repeatedly -> after 5 tries: 429 "rate limited".
    3. In Repeater/Intruder add header  X-Forwarded-For: 1.2.3.<n>  and vary
       <n> per request -- the limit never trips.
    4. Confirm success: GET /flag -- solved only once a login has actually
       succeeded AFTER more than 5 real attempts from the same underlying
       connection, proving the per-header limit was bypassed.

Fix: rate-limit on the real socket peer (or only a trusted proxy chain);
never trust client-supplied X-Forwarded-For for security decisions.
"""

from flask import Flask, request, jsonify
from collections import defaultdict
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-30-rate-limit-bypass").hexdigest()[:16]
attempts = defaultdict(int)
real_attempts = defaultdict(int)   # keyed by the true connection, not X-Forwarded-For
STATE = {"bypassed": False}


@app.route("/")
def index():
    return ('<form method="post" action="/login">'
            '<input name="user"><input name="pass"><button>login</button></form>')


@app.route("/login", methods=["GET", "POST"])
def login():
    # VULN: "client IP" taken from the spoofable X-Forwarded-For header.
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    attempts[ip] += 1
    real_attempts[request.remote_addr] += 1
    if attempts[ip] > 5:
        return "rate limited", 429
    if request.form.get("user") == "admin" and request.form.get("pass") == "letmein":
        if real_attempts[request.remote_addr] > 5:
            # The true connection made MORE than 5 attempts total, yet the
            # spoofed X-Forwarded-For rotation kept the per-header counter
            # under the limit -- the bypass genuinely worked.
            STATE["bypassed"] = True
        return "Welcome admin"
    return "bad credentials (attempt %d)" % attempts[ip], 401


@app.route("/flag")
def flag_route():
    if STATE["bypassed"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5030, debug=False)
