"""
Lab 35 -- Password-reset token reuse (token never invalidated).

/reset accepts a token and lets the holder set a new password, but never
marks the token used -- so the same link works repeatedly, including after
the password was already changed (an attacker who once saw the link keeps
control).

In Nullock:
    1. nullock scope add http://localhost:5035/*
    2. POST /reset token=abc123 password=new1   -> success
    3. Replay the SAME request with password=attacker -- still succeeds.
    4. Confirm success: GET /flag -- solved only once the SAME token was
       actually accepted by /reset two or more times.

Fix: single-use tokens -- invalidate on first use (and on expiry / after a
successful password change); store a hash, not the raw token.
"""

from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-35-reset-token-reuse").hexdigest()[:16]
TOKENS = {"abc123": "victim"}      # token -> user (issued out of band)
PASSWORDS = {"victim": "old"}
TOKEN_USES = {}


@app.route("/")
def index():
    return "POST /reset with token=abc123 & password=..."


@app.route("/reset", methods=["POST"])
def reset():
    token = request.form.get("token", "")
    newpw = request.form.get("password", "")
    user = TOKENS.get(token)
    if not user:
        return "invalid token", 403
    # VULN: token is NOT consumed/invalidated -- reusable forever.
    PASSWORDS[user] = newpw
    TOKEN_USES[token] = TOKEN_USES.get(token, 0) + 1
    return "password for %s set to '%s'" % (user, newpw)


@app.route("/flag")
def flag_route():
    if TOKEN_USES.get("abc123", 0) >= 2:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5035, debug=False)
