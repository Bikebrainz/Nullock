"""
Lab 12 -- Broken access control via missing auth check on admin endpoint.

The /admin/delete-user endpoint accepts a user id and deletes the
account. There's a /login that grants a session cookie, and the
non-admin endpoints check it -- but /admin/delete-user does not.
A regular logged-in user (or even an anonymous request) can purge
the user database.

Run:
    pip install flask
    python app.py

In Nullock:
    1. POST /login {"user":"alice","password":"secret"} -- get session cookie.
    2. GET /users -- list, auth required.
    3. POST /admin/delete-user?id=2 with NO cookie. Should require admin.
       Actual response: { "deleted": "bob" }. Forbidden bug.
    4. GET /users again -- bob is gone.
    5. Confirm success: GET /flag -- returns the flag once a delete has
       actually gone through with no admin session behind it, which the
       login flow here can never produce (is_admin is always False).
    6. Real fix: every admin route uses a single decorator that checks
       BOTH "logged in" AND "is_admin". Most often-missed: lateral
       admin endpoints under "internal" prefixes.
"""

import hashlib
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = "lab-12"

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-12-broken-access").hexdigest()[:16]
USERS = {1: "alice", 2: "bob", 3: "carol"}
DELETED_WITHOUT_ADMIN = {"happened": False}

def require_session():
    if "user" not in session:
        return jsonify(error="login required"), 401
    return None

@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    if body.get("user") and body.get("password"):
        session["user"] = body["user"]
        session["is_admin"] = False
        return jsonify(ok=True)
    return jsonify(error="bad creds"), 401

@app.route("/users")
def users():
    if (err := require_session()): return err
    return jsonify(users=USERS)

@app.route("/admin/delete-user", methods=["POST"])
def delete_user():
    # VULN: no auth check at all. Should require_session() + check is_admin.
    uid = int(request.args.get("id", "0"))
    is_admin = session.get("is_admin", False)
    name = USERS.pop(uid, None)
    if name and not is_admin:
        DELETED_WITHOUT_ADMIN["happened"] = True
    return jsonify(deleted=name)

@app.route("/flag")
def flag():
    if DELETED_WITHOUT_ADMIN["happened"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5012, debug=False)
