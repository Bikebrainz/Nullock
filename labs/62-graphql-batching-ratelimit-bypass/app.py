"""
Lab 62 -- GraphQL query batching bypasses a per-request rate limit.

/graphql accepts either a single operation object or a JSON ARRAY of
operation objects ("batching" -- a real, common GraphQL server feature
meant to save round-trips). The rate limiter here is naive: it counts
HTTP requests per IP, not the operations inside them. Sent one login
mutation at a time, an attacker is locked out after 3 tries -- looks
safe. Sent as a single batched array of many login mutations, the whole
guess list rides in ONE HTTP request, so the limiter only ever sees "1"
and never trips, no matter how many passwords are inside.

In Nullock:
    1. nullock scope add http://localhost:5062/*
    2. Confirm the limiter is real: in Repeater, POST /graphql four times
       with {"query": "mutation login", "variables": {"username": "admin",
       "password": "password123"}} -- each returns
       {"data": {"login": {"ok": false, "token": null}}}, and the 4th
       comes back 429 rate limited. A Nullock Intruder sniper run against
       this endpoint (one HTTP request per payload) hits the same wall.
    3. The bypass: send ONE POST /graphql whose body is a JSON ARRAY, one
       login-mutation object per candidate password below (25 entries --
       well past the 3-request limit, but it's still a single HTTP
       request):
           password123, admin123, letmein, qwerty2026, summer2026,
           spring2026, dragon99, Tr0ub4dor&3, hunter2, admin!2026,
           P@ssw0rd, changeme, welcome1, football7, monkey123, shadow88,
           master01, superman1, batman123, iloveyou1, princess7,
           abc12345, trustno1, sunshine9, nullock62
       Each array entry: {"query": "mutation login", "variables":
       {"username": "admin", "password": "<candidate>"}}.
    4. The response is a JSON array of 25 results, positionally matching
       the request array. Inspect it in Nullock's Inspector: one entry
       (the last candidate, nullock62) has "ok": true and a token --
       the whole guess list cost the limiter exactly one count.
    5. GET /flag with header "Authorization: Bearer <token>".
    6. Real fix: rate-limit by the number of operations actually
       executed (walk the batch array server-side and charge the limiter
       once per operation, not once per HTTP request), or reject/cap
       batch size on sensitive mutations like login outright.
"""

import hashlib
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-62-graphql-batching-ratelimit-bypass").hexdigest()[:16]

CANDIDATES = [
    "password123", "admin123", "letmein", "qwerty2026", "summer2026",
    "spring2026", "dragon99", "Tr0ub4dor&3", "hunter2", "admin!2026",
    "P@ssw0rd", "changeme", "welcome1", "football7", "monkey123",
    "shadow88", "master01", "superman1", "batman123", "iloveyou1",
    "princess7", "abc12345", "trustno1", "sunshine9", "nullock62",
]
ADMIN_PASSWORD = CANDIDATES[-1]
RATE_LIMIT = 3

attempts = {}
sessions = {}


def _execute(op):
    op = op or {}
    query = op.get("query", "")
    variables = op.get("variables", {}) or {}
    if "login" not in query:
        return {"errors": [{"message": "unknown operation"}]}
    username = variables.get("username", "")
    password = variables.get("password", "")
    if username == "admin" and password == ADMIN_PASSWORD:
        token = secrets.token_hex(8)
        sessions[token] = "admin"
        return {"data": {"login": {"ok": True, "token": token}}}
    return {"data": {"login": {"ok": False, "token": None}}}


@app.route("/")
def index():
    return "POST a GraphQL operation (or a JSON array of them) to /graphql."


@app.route("/graphql", methods=["POST"])
def graphql():
    # VULN: the limiter charges one count per HTTP request, no matter how
    # many operations are packed into a batched array body.
    ip = request.remote_addr
    attempts[ip] = attempts.get(ip, 0) + 1
    if attempts[ip] > RATE_LIMIT:
        return jsonify(error="rate limited, try again later"), 429

    body = request.get_json(silent=True)
    if body is None:
        return jsonify(error="bad json"), 400
    if isinstance(body, list):
        return jsonify([_execute(op) for op in body])
    return jsonify(_execute(body))


@app.route("/flag")
def flag_route():
    token = (request.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
    if sessions.get(token) != "admin":
        return jsonify(solved=False, reason="log in as admin first (see walkthrough step 4-5)"), 403
    return jsonify(solved=True, flag=FLAG)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5062, debug=False)
