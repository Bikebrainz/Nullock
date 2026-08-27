"""
Lab 52 -- LDAP injection (filter metacharacter injection + wildcard bypass).

A staff directory search (/search?cn=...) builds an LDAP-style search
filter by string concatenation, mirroring how the classic Java/JNDI and
python-ldap bugs actually happen. A single unescaped filter metacharacter
in the value either breaks the filter's syntax (a distinctive backend
error leaks) or -- with a well-formed wildcard -- widens the match past
what a literal-string blocklist expects, bypassing it entirely.

Run:
    pip install flask
    python app.py

In Nullock:
    1. nullock scope add http://localhost:5052/*
    2. GET /search?cn=alice -- one matching entry, no error: this is the
       baseline. GET /search?cn=admin -- 403 "restricted entry": the app
       blocklists that literal name so casual browsing can't find it.
    3. GET /search?cn=admi* -- 200, and the admin record (with its
       internal "notes" field) comes back anyway: the blocklist only
       ever compared the raw string, but the filter's own wildcard
       semantics matched "admin" without ever typing it.
    4. GET /search?cn=*)( -- 500, with a python-ldap-shaped error
       (ldap.FILTER_ERROR: unbalanced parentheses): the concatenated
       value broke the filter's syntax outright. Run the active probe
       (ldapi) against /search -- the filter-breaking probes it sends
       reproduce this exact error and it flags the cn param.
    5. Confirm success: GET /flag?cn=admi* -- solved only by a query that
       resolves to the admin entry without the literal string "admin".

Fix: never concatenate user input into an LDAP filter -- escape per RFC
4515 (or use a filter-builder API) before it reaches the query, and don't
rely on a literal-string blocklist for access control.
"""

import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-52-ldap-injection").hexdigest()[:16]

DIRECTORY = [
    {"cn": "alice", "title": "Engineer", "email": "alice@corp.local"},
    {"cn": "bob", "title": "Sales", "email": "bob@corp.local"},
    {"cn": "carol", "title": "Support", "email": "carol@corp.local"},
    {"cn": "admin", "title": "Directory Admin", "email": "admin@corp.local",
     "notes": "rotate the bind password quarterly"},
]


def build_filter(value):
    return "(cn=%s)" % value


def filter_error(flt):
    """Mimic a naive LDAP filter parser: track paren depth and reject any
    filter that closes its top-level group before the string ends (a stray
    ')' mid-value splits it into more than one top-level component, which
    real LDAP filter grammar rejects the same way python-ldap does)."""
    depth = 0
    for i, ch in enumerate(flt):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return "ldap.FILTER_ERROR: unbalanced parentheses"
            if depth == 0 and i != len(flt) - 1:
                return "ldap.FILTER_ERROR: unbalanced parentheses"
    if depth != 0:
        return "ldap.FILTER_ERROR: unbalanced parentheses"
    return None


def wildcard_match(pattern, text):
    if "*" not in pattern:
        return pattern == text
    import fnmatch
    return fnmatch.fnmatch(text, pattern)


def run_search(value):
    """Returns (status, body_dict_or_str). Raises the blocklist 403 only
    for the literal string 'admin' -- a wildcard that happens to resolve
    to it sails through, same class of bug as a WAF regex that only
    matches an exact keyword."""
    if value.strip().lower() == "admin":
        return 403, {"error": "restricted entry"}
    flt = build_filter(value)
    err = filter_error(flt)
    if err:
        return 500, err
    hits = [e for e in DIRECTORY if wildcard_match(value, e["cn"])]
    return 200, {"count": len(hits), "entries": hits}


@app.route("/")
def index():
    return ('<form method="get" action="/search">'
            '<input name="cn" value="alice"><button>search</button></form>')


@app.route("/search")
def search():
    status, body = run_search(request.args.get("cn", ""))
    if status == 500:
        return body, 500
    return jsonify(body), status


@app.route("/flag")
def flag():
    cn = request.args.get("cn", "")
    if cn.strip().lower() == "admin":
        return jsonify(solved=False), 403
    status, body = run_search(cn)
    if status == 200 and any(e["cn"] == "admin" for e in body["entries"]):
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5052, debug=False)
