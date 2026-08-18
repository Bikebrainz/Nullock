"""
Lab 20 -- Username enumeration via distinct login errors.

/login returns "Unknown username" for a non-existent account but "Wrong
password" for a real one -- so an attacker can enumerate valid usernames
without ever logging in.

In Nullock:
    1. nullock scope add http://localhost:5020/*
    2. Send /login to Intruder; fuzz the `user` field with a wordlist.
    3. Filter responses: a "Wrong password" body means the user exists.
    4. Confirm success: GET /flag?user=svcbot-4f2a -- a service account
       never shown on this page or in any docs, reachable only by
       walking the same "Wrong password" vs "Unknown username" oracle
       /login exposes against a wordlist that happens to include it.

Fix: return ONE generic message ("invalid username or password") for both
cases, and keep response timing constant (hash even for unknown users).
"""

import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-20-user-enumeration").hexdigest()[:16]
USERS = {"admin": "x", "alice": "y", "bob": "z", "svcbot-4f2a": "z9"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("user", "")
        p = request.form.get("pass", "")
        if u not in USERS:
            return "Unknown username", 401          # VULN: distinct message
        if USERS[u] != p:
            return "Wrong password", 401            # VULN: confirms the user exists
        return "Welcome"
    return ('<form method="post"><input name="user"><input name="pass">'
            '<button>login</button></form>')


@app.route("/flag")
def flag():
    # Reached only by discovering the hidden account through the same
    # "Unknown username" vs "Wrong password" oracle /login exposes --
    # it is never listed, linked, or documented anywhere else.
    u = request.args.get("user", "")
    if u == "svcbot-4f2a" and u in USERS:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5020, debug=False)
