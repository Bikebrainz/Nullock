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

Fix: rate-limit on the real socket peer (or only a trusted proxy chain);
never trust client-supplied X-Forwarded-For for security decisions.
"""

from flask import Flask, request
from collections import defaultdict

app = Flask(__name__)
attempts = defaultdict(int)


@app.route("/")
def index():
    return ('<form method="post" action="/login">'
            '<input name="user"><input name="pass"><button>login</button></form>')


@app.route("/login", methods=["GET", "POST"])
def login():
    # VULN: "client IP" taken from the spoofable X-Forwarded-For header.
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    attempts[ip] += 1
    if attempts[ip] > 5:
        return "rate limited", 429
    if request.form.get("user") == "admin" and request.form.get("pass") == "letmein":
        return "Welcome admin"
    return "bad credentials (attempt %d)" % attempts[ip], 401


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5030, debug=False)
