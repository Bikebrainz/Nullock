"""
Lab 80 -- GraphQL broken object-level authorization (the REST endpoint is
guarded, the GraphQL resolver for the exact same data isn't).

Two users, alice (invoice 1) and bob (invoice 2). The REST endpoint
`/api/invoice/<id>` does this right: it checks that the session's own
`sid` cookie maps to the invoice's owner before returning anything, so
alice fetching `/api/invoice/2` gets a clean 403. `/graphql` serves the
identical `Invoice { id amount owner }` data through a resolver that was
written later, reusing the REST handler's own auth-looks-solved intuition
-- it checks that a `sid` cookie names SOME logged-in user (so an
anonymous request is still rejected), but never compares that user against
the invoice id actually being resolved. Two different code paths for the
same object, one of them never re-derives the ownership check the other
one has. This is the shape Burp's own docs single out as the sleeper
BOLA case: a REST audit that stops at "the REST endpoint is fixed" misses
that the same backend data model is reachable through a second API
surface that never got the same review.

Nullock's `/api/authz-test` (multi-identity replay: same captured request,
different identities' headers/cookies, diverge-or-match comparison) is
built exactly for surfacing this -- and it works identically against a
GraphQL POST body, since GraphQL is just JSON over HTTP from the replay
engine's point of view. Capture one `/graphql` invoice(id:2) request as
alice, then AUTHZ TEST it against bob's identity: REST already told you
alice/bob get consistently *different* shapes on `/api/invoice`, so the
interesting result here is the opposite -- alice's session getting bob's
own 200+amount back is the finding, not a mismatch.

In Nullock:
    1. nullock scope add http://localhost:5080/*
    2. GET /login?user=alice, then GET /login?user=bob (in a second
       Repeater tab / different Cookie jar) -- each sets its own `sid`.
    3. As alice: GET /api/invoice/1 -- 200, your own invoice. GET
       /api/invoice/2 -- 403 (bob's, correctly refused). The REST surface
       looks solid.
    4. As alice: POST /graphql {"query": "{ invoice(id: 2) { id amount
       owner } }"} -- 200, with bob's full invoice (amount + owner) in
       the response, despite step 3 refusing the identical object over
       REST. Send this request to Repeater, then use the AUTHZ TEST
       button (or POST /api/authz-test {rowId, identities:[{name:"bob",
       headers:{"Cookie":"sid=<bob's sid>"}}]}) to confirm both
       identities land on the exact same 200 body -- ownership plays no
       part in the GraphQL resolver's decision at all.
    5. Confirm success: GET /flag with alice's `sid` cookie once you've
       pulled bob's invoice through /graphql.

Fix: authorization has to be enforced once, in the data-access layer both
paths call through -- not re-implemented (and inevitably forgotten) in
each API surface that happens to expose the same object.
"""

import hashlib
import re
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-80-graphql-bola-invoice").hexdigest()[:16]

USERS = {"alice": 1, "bob": 2}
INVOICES = {
    1: {"id": 1, "amount": 4820.00, "owner": "alice"},
    2: {"id": 2, "amount": 91340.00, "owner": "bob"},
}
SESSIONS = {}  # sid -> username
solved = {"leaked": False}


@app.route("/login")
def login():
    user = request.args.get("user", "")
    if user not in USERS:
        return jsonify(error="unknown user"), 400
    sid = secrets.token_hex(16)
    SESSIONS[sid] = user
    resp = jsonify(loggedIn=user)
    resp.set_cookie("sid", sid)
    return resp


def _current_user():
    return SESSIONS.get(request.cookies.get("sid", ""))


@app.route("/api/invoice/<int:invoice_id>")
def api_invoice(invoice_id):
    user = _current_user()
    if user is None:
        return jsonify(error="not logged in"), 401
    inv = INVOICES.get(invoice_id)
    if inv is None:
        return jsonify(error="not found"), 404
    # REST does this right: the session's own invoice id must match.
    if USERS[user] != invoice_id:
        return jsonify(error="forbidden"), 403
    return jsonify(inv)


@app.route("/graphql", methods=["POST"])
def graphql():
    user = _current_user()
    if user is None:
        return jsonify(errors=[{"message": "not logged in"}]), 401
    body = request.get_json(silent=True) or {}
    query = body.get("query", "")
    if "invoice" not in query:
        return jsonify(errors=[{"message": "query not recognised"}])
    m = re.search(r"id\s*:\s*(\d+)", query)
    if not m:
        return jsonify(errors=[{"message": "id required"}])
    invoice_id = int(m.group(1))
    inv = INVOICES.get(invoice_id)
    if inv is None:
        return jsonify(data={"invoice": None})
    # VULN: confirms `user` is SOMEONE logged in, but never checks that
    # `user` owns `invoice_id` -- the ownership check the REST handler
    # above has is simply absent from this resolver.
    if USERS[user] != invoice_id:
        solved["leaked"] = True
    return jsonify(data={"invoice": inv})


@app.route("/flag")
def flag():
    if not solved["leaked"]:
        return jsonify(solved=False), 403
    return jsonify(solved=True, flag=FLAG)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5080, debug=False)
