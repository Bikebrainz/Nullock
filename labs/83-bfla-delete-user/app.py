"""
Lab 83 -- Broken function level authorization: the destructive admin action never got the same role check its sibling admin views did.

This app has three admin-only functions. Two of them are gated correctly:
GET /admin/users and GET /admin/stats both require a logged-in session
AND is_admin=True, returning 403 to anyone else. The third, POST
/admin/delete-user, is the one that actually does something dangerous --
and its handler only checks that a session exists, not what role it
belongs to. Any logged-in user, admin or not, can delete any other
account.

This is OWASP API5:2023 (Broken Function Level Authorization): distinct
from Lab 12 (no auth check at all -- even an anonymous request gets in)
in that this app's authorization is real and mostly correct. A scanner
or reviewer that only ever tests the well-known admin views (the two
that behave exactly as expected) would sign off on this app's access
control entirely, having never touched the one action a regular,
properly-authenticated user can still reach. Also distinct from Lab 80's
BOLA and Lab 81's shadow-API IDOR (which OBJECT a request can reach) --
here every function is object-agnostic (id is just which account to
delete), the gap is purely which FUNCTION a given ROLE may call.

Run:
    pip install flask
    python app.py

In Nullock:
    1. nullock scope add http://localhost:5083/*
    2. POST /login {"user":"alice","password":"x"} -- alice is a regular,
       non-admin account. Keep the session cookie.
    3. GET /admin/users with alice's cookie -- 403. GET /admin/stats --
       403 too. Both admin views are gated correctly; this is not Lab 12.
    4. POST /admin/delete-user?id=2 with the SAME alice cookie -- 200
       {"deleted": "bob"}. The one admin action that forgot the check
       every other admin route has.
    5. Confirm success: GET /flag -- flips true only once a delete has
       gone through behind an authenticated session that was never an
       admin session.

Fix: authorization must be checked per FUNCTION, not just per session --
put every admin route (views AND actions) behind the same require_admin()
decorator, and add a test that walks the route table asserting each
/admin/* handler actually calls it, so a new action can't be added
without one.
"""

import hashlib
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = "lab-83"

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-83-bfla-delete-user").hexdigest()[:16]

USERS = {
    1: {"username": "alice", "is_admin": False},
    2: {"username": "bob", "is_admin": False},
    3: {"username": "admin", "is_admin": True},
}
BY_NAME = {u["username"]: uid for uid, u in USERS.items()}
DELETED_BY_NON_ADMIN = {"happened": False}


def require_session():
    if "user" not in session:
        return jsonify(error="login required"), 401
    return None


def require_admin():
    err = require_session()
    if err:
        return err
    if not session.get("is_admin"):
        return jsonify(error="admin required"), 403
    return None


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    name = body.get("user")
    uid = BY_NAME.get(name)
    if uid is None or not body.get("password"):
        return jsonify(error="bad creds"), 401
    session["user"] = name
    session["is_admin"] = USERS[uid]["is_admin"]
    return jsonify(ok=True, is_admin=USERS[uid]["is_admin"])


@app.route("/admin/users")
def admin_users():
    if (err := require_admin()):
        return err
    return jsonify(users=[u["username"] for u in USERS.values()])


@app.route("/admin/stats")
def admin_stats():
    if (err := require_admin()):
        return err
    return jsonify(total_users=len(USERS))


@app.route("/admin/delete-user", methods=["POST"])
def delete_user():
    # VULN: only require_session() -- checks you're logged in, never that
    # you're an admin. Its two siblings above both call require_admin().
    if (err := require_session()):
        return err
    uid = int(request.args.get("id", "0"))
    victim = USERS.pop(uid, None)
    if victim is None:
        return jsonify(error="not found"), 404
    if not session.get("is_admin"):
        DELETED_BY_NON_ADMIN["happened"] = True
    return jsonify(deleted=victim["username"])


@app.route("/flag")
def flag_route():
    if DELETED_BY_NON_ADMIN["happened"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5083, debug=False)
