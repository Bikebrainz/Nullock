"""
Lab 54 -- XPath injection (error-based confirm + boolean login bypass).

A staff login endpoint builds an XPath query against an in-memory XML user
store by plain string concatenation -- the same class of bug as SQLi, just
against `lxml`/libxml2 instead of a SQL engine. A single unescaped quote in
either field breaks the expression's syntax outright (a real `XPathEvalError`
leaks back), and a well-formed boolean payload widens the predicate past
what the credential check was supposed to require.

Run:
    pip install flask lxml
    python app.py

In Nullock:
    1. nullock scope add http://localhost:5054/*
    2. GET /login?username=alice&password=wrong -- 401, no match: this is
       the baseline (no XPath error, just "invalid credentials").
    3. GET /login?username=alice'&password=x -- 400, with a real
       `lxml.etree.XPathEvalError: Invalid predicate` echoed back: the lone
       quote in `username` closes the string literal early and the rest of
       the expression no longer parses. Run the active probe (xpathi)
       against /login -- its expression-breaker probes reproduce this exact
       error on the `username` param (it's in the probe's default param
       list) and it flags the finding, corroborated against a benign value
       that does NOT error.
    4. Exploit the same class of bug for a login bypass: GET
       /login?username=admin&password=' or 1=1 or 'a'='a -- 200, logged in
       as admin. The query becomes
       `//user[username/text()='admin' and password/text()='' or 1=1 or 'a'='a']`
       and XPath's `and` binds tighter than `or`, so the standalone `1=1`
       term makes the whole predicate true regardless of the real password
       -- the match count jumps from the at-most-one a legitimate login
       ever produces to all three directory entries, and the app trusts
       the *typed* username for who got logged in.
    5. Confirm success: GET /flag?username=admin&password=' or 1=1 or 'a'='a

Fix: never concatenate user input into an XPath expression -- parameterize
the query (e.g. an XPath variable binding) or escape per the same
untrusted-input discipline as SQL, and never let credential-check success
alone decide identity -- verify the returned node actually IS the account
being logged into.
"""

import hashlib

from flask import Flask, jsonify, request
from lxml import etree

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-54-xpath-injection").hexdigest()[:16]

USERS_XML = b"""<users>
  <user><username>alice</username><password>alicepw123</password><role>user</role></user>
  <user><username>bob</username><password>bobpw456</password><role>user</role></user>
  <user><username>admin</username><password>correcthorsebatterystaple</password><role>admin</role></user>
</users>"""

TREE = etree.fromstring(USERS_XML)
ROLES = {u.findtext("username"): u.findtext("role") for u in TREE.findall("user")}


def run_login(username, password):
    """Returns (status, body_dict). VULN: string-concatenated XPath query;
    a non-empty result is treated as "credentials accepted" and the role is
    then looked up by the *submitted* username, not the matched node -- so
    a boolean-true injection in either field logs the attacker in as
    whichever username they typed, no matching password required."""
    query = "//user[username/text()='%s' and password/text()='%s']" % (username, password)
    try:
        matches = TREE.xpath(query)
    except etree.XPathEvalError as e:
        return 400, {"error": "%s: %s" % (type(e).__name__, e)}
    if not matches:
        return 401, {"error": "invalid credentials"}
    role = ROLES.get(username)
    if role is None:
        return 401, {"error": "invalid credentials"}
    return 200, {"logged_in": True, "username": username, "role": role,
                 "matchCount": len(matches)}


@app.route("/")
def index():
    return ('<form method="get" action="/login">'
            '<input name="username" value="alice">'
            '<input name="password" type="password">'
            '<button>login</button></form>')


@app.route("/login")
def login():
    status, body = run_login(request.args.get("username", ""), request.args.get("password", ""))
    return jsonify(body), status


@app.route("/flag")
def flag():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    status, body = run_login(username, password)
    if status == 200 and username == "admin" and body.get("matchCount", 0) > 1:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5054, debug=False)
