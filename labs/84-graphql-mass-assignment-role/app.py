"""
Lab 84 -- GraphQL mass assignment: the REST profile update allow-lists its
fields, the GraphQL mutation for the exact same record merges whatever the
client sends.

`PUT /api/profile` does mass assignment right: it reads the request body
and copies over ONLY `bio` and `email` -- even if the JSON also carries
`role` or `is_admin`, those keys are never looked at, so a regular user
POSTing `{"bio": "hi", "role": "admin"}` still ends up a regular user.
`POST /graphql`'s `updateProfile` mutation was written later against the
same USERS record, and takes a shortcut: it parses every `field: "value"`
pair out of the mutation's argument list and applies the whole dict
straight onto the user with no allow-list at all, `role` included --
because CWE-915 (mass assignment) is a per-field-name defect and each API
surface here declares its own field list, fixing the REST handler did
nothing for the resolver sitting right next to it.

Distinct from Lab 18 (mass assignment via a single REST endpoint with no
allow-list anywhere) in that THIS app's REST endpoint is not the bug --
it is the control that makes the finding interesting: an auditor who only
throws extra fields at `/api/profile` and watches them get stripped would
reasonably conclude mass assignment is handled here. It's also distinct
from Lab 80's GraphQL BOLA (same object, different identity) -- here
there is only ever one user acting on their own record; the gap is which
FIELDS of that record a mutation lets the caller set, not which record.

In Nullock:
    1. nullock scope add http://localhost:5084/*
    2. GET /login?user=alice -- sets a session cookie. alice starts non-admin.
    3. As alice: PUT /api/profile {"bio":"hi","role":"admin"} -- 200, but
       GET /api/profile shows role is still "user". The allow-listed REST
       path is safe.
    4. As alice: POST /graphql {"query": "mutation { updateProfile(bio:
       \\"hi\\", role: \\"admin\\") { username role } }"} -- 200, and the
       response's `role` now reads "admin". The resolver applied the
       field REST would have dropped.
    5. Confirm success: GET /flag with alice's cookie -- flips true only
       once a session that logged in non-admin has `is_admin=True` set
       through the GraphQL mutation specifically (not by editing the
       in-memory USERS table any other way).

Fix: the resolver must build its own allow-listed update dict the same
way the REST handler does (or, better, both call one shared
`apply_profile_update(user, **allowed_fields)` helper) instead of merging
the mutation's raw argument dict onto the record.
"""

import hashlib
import re
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-84-graphql-mass-assignment-role").hexdigest()[:16]

USERS = {
    "alice": {"bio": "", "email": "alice@example.com", "role": "user"},
}
SESSIONS = {}  # sid -> username
GRAPHQL_PROMOTED = {"happened": False}


@app.route("/login")
def login():
    user = request.args.get("user", "")
    if user not in USERS:
        return jsonify(error="unknown user"), 400
    sid = secrets.token_hex(16)
    SESSIONS[sid] = user
    resp = jsonify(loggedIn=user, role=USERS[user]["role"])
    resp.set_cookie("sid", sid)
    return resp


def _current_user():
    return SESSIONS.get(request.cookies.get("sid", ""))


@app.route("/api/profile", methods=["GET", "PUT"])
def api_profile():
    user = _current_user()
    if user is None:
        return jsonify(error="not logged in"), 401
    record = USERS[user]
    if request.method == "PUT":
        body = request.get_json(silent=True) or {}
        # Correct: only these two fields are ever copied, whatever else
        # the body contains (role/is_admin included) is ignored.
        for field in ("bio", "email"):
            if field in body:
                record[field] = body[field]
    return jsonify(username=user, **record)


@app.route("/graphql", methods=["POST"])
def graphql():
    user = _current_user()
    if user is None:
        return jsonify(errors=[{"message": "not logged in"}]), 401
    body = request.get_json(silent=True) or {}
    query = body.get("query", "")
    m = re.search(r"updateProfile\s*\(([^)]*)\)", query)
    if not m:
        return jsonify(errors=[{"message": "query not recognised"}])
    args_src = m.group(1)
    # VULN: every "field: \"value\"" pair in the argument list is applied
    # straight onto the record -- no allow-list, unlike /api/profile above.
    record = USERS[user]
    was_admin_role = record["role"] == "admin"
    for field, value in re.findall(r'(\w+)\s*:\s*"((?:[^"\\]|\\.)*)"', args_src):
        record[field] = value.replace('\\"', '"')
    if record["role"] == "admin" and not was_admin_role:
        GRAPHQL_PROMOTED["happened"] = True
    return jsonify(data={"updateProfile": {"username": user, **record}})


@app.route("/flag")
def flag():
    if not GRAPHQL_PROMOTED["happened"]:
        return jsonify(solved=False), 403
    return jsonify(solved=True, flag=FLAG)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5084, debug=False)
