"""
Lab 35 -- Password-reset token reuse (token never invalidated).

/reset accepts a token and lets the holder set a new password, but never
marks the token used -- so the same link works repeatedly, including after
the password was already changed (an attacker who once saw the link keeps
control).

In Nullock:
    1. nullock scope ... add http://localhost:5035/*
    2. POST /reset token=abc123 password=new1   -> success
    3. Replay the SAME request with password=attacker -- still succeeds.

Fix: single-use tokens -- invalidate on first use (and on expiry / after a
successful password change); store a hash, not the raw token.
"""

from flask import Flask, request

app = Flask(__name__)
TOKENS = {"abc123": "victim"}      # token -> user (issued out of band)
PASSWORDS = {"victim": "old"}


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
    return "password for %s set to '%s'" % (user, newpw)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5035, debug=False)
