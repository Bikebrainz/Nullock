"""
Lab 17 -- NoSQL injection (operator) auth bypass.

The login endpoint emulates a MongoDB-style query. Supplying the password
as an operator object via bracket notation -- password[$ne]=x -- matches
any user, bypassing the password check entirely (the classic
{"$ne": null} trick).

In Nullock:
    1. nullock scope ... add http://localhost:5017/*
    2. POST /login with  username=admin&password=wrong   -> 401 denied
    3. Send to Repeater, change the body to:
           username=admin&password[$ne]=x
    4. You're authenticated -- the $ne operator matched any password.
    5. Run the active probe (nosqli): the literal vs $ne vs $eq
       differential (gated on a stability baseline) confirms it.

Fix: cast user inputs to strings before querying; reject operator
objects (dict-shaped values) in user-supplied auth fields.
"""

from flask import Flask, request

app = Flask(__name__)
USERS = {"admin": "S3cr3t!"}


def matches(stored, supplied):
    # Emulate Mongo operator semantics on a user-supplied value.
    if isinstance(supplied, dict):
        if "$ne" in supplied:
            return stored != supplied["$ne"]
        if "$gt" in supplied:
            return stored > str(supplied["$gt"])
        return False
    return stored == supplied


@app.route("/")
def index():
    return ('<form method="post" action="/login">'
            '<input name="username" value="admin">'
            '<input name="password"><button>login</button></form>')


@app.route("/login", methods=["POST"])
def login():
    form = request.form
    username = form.get("username", "")
    # Reconstruct an operator object from bracket notation:
    #   password=...        -> a plain string
    #   password[$ne]=...   -> {"$ne": "..."}
    pw = None
    for k in form:
        if k == "password":
            pw = form[k]
        elif k.startswith("password[") and k.endswith("]"):
            pw = {k[len("password["):-1]: form[k]}
    stored = USERS.get(username)
    if stored is not None and matches(stored, pw):
        return "Welcome %s! (authenticated)" % username
    return "Invalid credentials", 401


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5017, debug=False)
