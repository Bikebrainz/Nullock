"""
Lab 81 -- Shadow API: a forgotten v1 endpoint never got v2's ownership check.

The app shipped `/api/v1/users/<id>` a while back, no auth on it at all
-- an internal-only endpoint that leaked out. When account data started
carrying an `apiKey` field, someone wrote `/api/v2/users/<id>` properly:
session-authenticated, and the session's own user id has to match the id
being requested. v1 was supposed to be retired the same day. It wasn't
-- the route is still mounted, still reachable, and still returns the
full record (apiKey included) for ANY id, logged in or not. Nobody
scanning the current API surface even knows to look for it: it's not
linked from the app, not in the OpenAPI doc `/openapi.json` serves, and
the only trace is the version number itself.

This is OWASP API9:2023 (Improper Inventory Management) wearing an IDOR
costume: the vulnerable object-access bug was already fixed once, in the
endpoint everyone reviews. It survives in a second, unlisted endpoint
serving the identical data model. A REST audit that only walks the
documented v2 surface -- or an IDOR probe that only ever got pointed at
`/api/v2/users/<id>` -- reports clean and is wrong.

Nullock's content-discovery engine (DISCOVER tab / `/api/discover`) is
built to catch exactly this: seed it with the known `/api/v2/users/1`
path and a wordlist that includes short segments like `v1`, `v2`, `v3`,
and it will find the sibling `/api/v1/users/1` that no page links to.
Once found, `/api/idor/test` (or the uniform TESTS tab's `idor` type)
against `/api/v1/users/<id>` confirms the same numeric-id-walk that v2
correctly blocks succeeds unauthenticated on v1.

In Nullock:
    1. nullock scope add http://localhost:5081/*
    2. GET /login?user=alice -- sets a `sid` cookie (alice is user id 1).
    3. As alice: GET /api/v2/users/2 -- 403 (bob's record, correctly
       refused; v2's ownership check works).
    4. Run content discovery against /api/v2/users/1 with a wordlist
       containing `v1` (or just try it by hand): GET /api/v1/users/2 --
       no Cookie header needed at all -- 200, with bob's full record
       including `apiKey`. The endpoint v2 was written to replace is
       still live and was never brought up to the same standard.
    5. Confirm success: GET /flag once you've pulled a v1 record for a
       user id you don't own.

Fix: retire v1 for real (405/410 the route, or better, remove it from
the router entirely) the same day v2 ships, and audit an API's full
version history, not just the currently-documented surface, before
calling authorization "fixed".
"""

import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-81-shadow-api-v1-idor").hexdigest()[:16]

USERS = {"alice": 1, "bob": 2}
RECORDS = {
    1: {"id": 1, "username": "alice", "email": "alice@example.com", "apiKey": "sk_alice_7f3a9c"},
    2: {"id": 2, "username": "bob", "email": "bob@example.com", "apiKey": "sk_bob_1d8e02"},
}
SESSIONS = {}  # sid -> username
solved = {"exposed": False}


@app.route("/login")
def login():
    user = request.args.get("user", "")
    if user not in USERS:
        return jsonify(error="unknown user"), 400
    import secrets
    sid = secrets.token_hex(16)
    SESSIONS[sid] = user
    resp = jsonify(loggedIn=user)
    resp.set_cookie("sid", sid)
    return resp


def _current_user():
    return SESSIONS.get(request.cookies.get("sid", ""))


@app.route("/openapi.json")
def openapi():
    # Only v2 is documented -- v1 was meant to be gone by now.
    return jsonify({
        "openapi": "3.0.0",
        "paths": {"/api/v2/users/{id}": {"get": {"summary": "Get a user record (owner only)"}}},
    })


@app.route("/api/v2/users/<int:user_id>")
def api_v2_users(user_id):
    user = _current_user()
    if user is None:
        return jsonify(error="not logged in"), 401
    if USERS[user] != user_id:
        return jsonify(error="forbidden"), 403
    return jsonify(RECORDS.get(user_id, {}))


@app.route("/api/v1/users/<int:user_id>")
def api_v1_users(user_id):
    # VULN: the route the app forgot to retire. No auth, no ownership
    # check -- whatever v2 does today, v1 still does nothing.
    rec = RECORDS.get(user_id)
    if rec is None:
        return jsonify(error="not found"), 404
    user = _current_user()
    if user is None or USERS[user] != user_id:
        solved["exposed"] = True
    return jsonify(rec)


@app.route("/flag")
def flag():
    if not solved["exposed"]:
        return jsonify(solved=False), 403
    return jsonify(solved=True, flag=FLAG)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5081, debug=False)
