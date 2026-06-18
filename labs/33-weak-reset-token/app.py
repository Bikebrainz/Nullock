"""
Lab 33 -- Weak / predictable password-reset tokens.

/forgot issues a reset token that is a pure function of the (public)
username -- md5("reset-" + user) -- so anyone can recompute a victim's token
and reset their password.

In Nullock:
    1. nullock scope add http://localhost:5033/*
    2. POST /forgot user=victim -- note the token.
    3. The token == md5("reset-victim"); GET /reset?user=victim&token=<that>
       succeeds for anyone who knows the username.

Fix: generate tokens with a CSPRNG (secrets.token_urlsafe), bind them to the
account with a short expiry, and store only a hash.
"""

from flask import Flask, request
import hashlib

app = Flask(__name__)


def weak_token(user):
    # VULN: token derived only from the public username.
    return hashlib.md5(("reset-" + user).encode()).hexdigest()


@app.route("/")
def index():
    return ('<form method="post" action="/forgot">'
            '<input name="user" value="victim"><button>reset</button></form>')


@app.route("/forgot", methods=["POST"])
def forgot():
    user = request.form.get("user", "")
    return "reset token for %s: %s" % (user, weak_token(user))


@app.route("/reset")
def reset():
    user = request.args.get("user", "")
    token = request.args.get("token", "")
    if token and token == weak_token(user):
        return "valid token -- %s may set a new password" % user
    return "invalid token", 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5033, debug=False)
