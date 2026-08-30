"""
Lab 67 -- GraphQL query-depth DoS (no server-side depth limit).

Hosts a minimal GraphQL introspection endpoint at /graphql. The schema
resolver happily walks the `__Type.ofType` chain to whatever nesting depth
the client's query asks for -- there is no cap. A real production GraphQL
server needs an explicit depth-limit rule (e.g. graphql-depth-limit) or an
attacker can nest a query hundreds or thousands of levels deep to blow up
parse/execution cost, a classic GraphQL DoS vector.

This is exactly the misconfiguration Nullock's built-in active probe
`graphql-depth-bypass` (POST /api/graphql/probe) targets. That probe sends
the schema-VALID self-recursive introspection query
    {__schema{types{ofType{ofType{ofType{ofType{ofType{ofType{ofType{ofType{name}}}}}}}}}}}
(8 nested `ofType` hops, depth ~11 overall) because `ofType` is a real,
always-queryable field on the `__Type` introspection type -- unlike a
fabricated field name, GraphQL can never reject it for "field does not
exist", so the ONLY thing that can make a well-behaved server refuse it is
an actual depth-limit rule. A server with no such rule answers with
`"data"` present; a depth-limited (or introspection-disabled) server
answers with only `"errors"` and no `"data"`.

Run:
    pip install flask
    python app.py

In Nullock:
    1. Set scope to http://localhost:5067/* (or use the pre-set project
       file), then confirm introspection is on:
       POST /graphql {"query": "{ __schema { types { name } } }"}.
    2. Run the built-in GraphQL active probe (PROBE tab's GraphQL toolkit,
       or POST /api/graphql/probe {"url": "http://localhost:5067/graphql"})
       -- the graphql-depth-bypass attack fires, because this server answers
       the 8-hop `ofType` chain query with real `"data"` instead of
       rejecting it for excessive depth.
    3. Confirm by hand: POST the same deep query yourself and see `"data"`
       come back with a fully-resolved 8-level-deep `ofType` chain -- proof
       the server will walk however deep you ask it to.
    4. GET /flag once you've sent a query with an `ofType` chain at least
       as deep as the probe's (8 hops) and gotten `"data"` back for it.
    5. Real fix: add a query-depth-limit validation rule (reject the query
       document before execution once nesting exceeds a small fixed
       maximum, e.g. 5-10) rather than trusting resolvers to bound
       themselves.
"""

import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-67-graphql-depth-dos").hexdigest()[:16]

# The probe's own trigger depth: 8 nested "ofType" hops.
DEPTH_THRESHOLD = 8

deepest_seen = {"depth": 0}


def oftype_depth(query):
    return query.count("ofType")


def build_nested_ofType(depth):
    # VULN: recurses however deep the caller asks -- no cap. A real
    # depth-limited server would refuse the query document outright
    # instead of ever reaching a resolver.
    node = {"name": "Int", "ofType": None}
    for _ in range(depth):
        node = {"name": None, "ofType": node}
    return node


@app.route("/graphql", methods=["POST"])
def graphql():
    body = request.get_json(silent=True) or {}
    q = body.get("query", "")
    if "__schema" not in q or "types" not in q:
        return jsonify({"errors": [{"message": "query not recognised"}]})
    depth = oftype_depth(q)
    if depth > deepest_seen["depth"]:
        deepest_seen["depth"] = depth
    inner = build_nested_ofType(depth)
    return jsonify({"data": {"__schema": {"types": [{"name": "Query", "ofType": inner}]}}})


@app.route("/flag", methods=["GET"])
def flag():
    if deepest_seen["depth"] >= DEPTH_THRESHOLD:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5067, debug=False)
