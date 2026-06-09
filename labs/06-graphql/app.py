"""
Lab 06 -- GraphQL introspection + over-fetching.

Hosts a GraphQL endpoint at /graphql. Has introspection enabled in
production, and the `user(id)` resolver returns the user's password
hash because the schema wasn't carefully partitioned.

Run:
    pip install flask
    python app.py

In Nullock:
    1. POST to /graphql with body { "query": "{ __schema { types { name } } }" }
       -- get the full schema via introspection.
    2. From that, learn there's a `user(id)` resolver returning email
       AND password_hash.
    3. POST query { user(id: 1) { name email password_hash } } -- get
       alice's password hash. Crackable with hashcat.
    4. Walk every user with Intruder: payload set [1..100], substituting
       into the id field.
    5. Real fix: disable introspection in prod, scope sensitive fields
       behind a `requires_admin` directive checked in the resolver.
"""

import json
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {
    1: {"name": "alice", "email": "alice@example.com",
        "password_hash": "$2b$12$KIXxV..."},   # bcrypt placeholder
    2: {"name": "bob",   "email": "bob@example.com",
        "password_hash": "$2b$12$KIXyW..."},
}

SCHEMA = {
    "types": [
        { "name": "User", "fields": [
            { "name": "id" }, { "name": "name" },
            { "name": "email" }, { "name": "password_hash" },
        ]},
        { "name": "Query", "fields": [
            { "name": "user(id: Int!): User" },
        ]},
    ]
}

def parse_query(q):
    q = q.strip()
    # Cheap parser -- looks for { __schema { ... } } or { user(id: N) { ... } }.
    if "__schema" in q:
        return { "data": { "__schema": SCHEMA } }
    if q.startswith("{ user(id:"):
        try:
            tail = q.split("user(id:")[1]
            uid_str = tail.split(")")[0].strip()
            uid = int(uid_str)
            if uid not in USERS:
                return { "data": { "user": None } }
            # VULN: just dumps every field; doesn't filter password_hash.
            return { "data": { "user": USERS[uid] } }
        except (ValueError, IndexError):
            return { "errors": [{ "message": "bad id" }] }
    return { "errors": [{ "message": "query not recognised" }] }

@app.route("/graphql", methods=["POST"])
def graphql():
    body = request.get_json(silent=True) or {}
    q = body.get("query", "")
    return jsonify(parse_query(q))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5006, debug=False)
