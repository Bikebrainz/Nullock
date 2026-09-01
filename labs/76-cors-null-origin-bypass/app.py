"""
Lab 76 -- CORS null-origin bypass: an allow-list that trusts "null" for local testing.

/api/wallet returns the logged-in user's balance, gated by a real CORS
allow-list: ALLOWED_ORIGIN_RE = re.compile(r"^https://partner-[a-z]+\.nullock-corp\.test$")
checks the Origin header with a properly ANCHORED regex (^...$, unlike Lab
69's missing trailing anchor) before ever reflecting it into
Access-Control-Allow-Origin, and only reflects a matching Origin together
with Access-Control-Allow-Credentials: true. Neither Lab 16's "reflect
anything" bug nor Lab 69's "unanchored regex" bug is present here -- an
arbitrary attacker.example Origin gets no CORS headers at all.

But the allow-list has one more branch: `if origin == "null": allow it
too`, added by a developer who wanted to test the API from a local
file://...html page during development (opening a local file makes the
browser send Origin: null) and never removed before shipping. The
literal string "null" is not something only a local file can send,
though -- a browser also sends it for a request that comes from a
SANDBOXED iframe with no `allow-same-origin` token
(`<iframe sandbox="allow-scripts allow-forms" src="https://attacker.example/poc.html">`),
from a `data:` URI navigation, or from some cross-origin redirect chains.
Any of those, hosted by an attacker, lets a real visiting browser send
Origin: null while still attaching the victim's own session cookie for
THIS site -- the sandbox restricts what the iframe's OWN origin can do,
not which cookies the browser sends to the target origin -- so the same
"null" branch a developer added for their own local-testing convenience
is reachable by anyone who can get a victim to load a sandboxed iframe or
a data: URI, with the victim's cookies riding along for free.

Nullock's automated CORS prober (`/api/cors/probe`) sends a handful of
crafted Origin values (an arbitrary attacker.example string, a subdomain
variant, a protocol-relative variant) to look for a reflected-and-
credentialed response, same shape as Lab 16 and Lab 69 -- but "null" is a
literal string, not a host pattern, so it doesn't fit the URL-host
mutation the prober applies and isn't in its candidate list, so the probe
reports no finding here. This is a Repeater find, same precedent as Lab
69's own literal-header edit.

In Nullock:
    1. nullock scope add http://localhost:5076/*
    2. Send /api/wallet to Repeater with header Origin: https://attacker.example
       -- no Access-Control-Allow-Origin comes back at all: the anchored
       allow-list correctly rejects an arbitrary origin.
    3. Change the header to Origin: null -- the response now carries
       Access-Control-Allow-Origin: null and
       Access-Control-Allow-Credentials: true.
    4. That is exactly what a victim's browser would send from a
       sandboxed iframe or a data: URI hosted by an attacker, with the
       victim's own session cookie still attached -- the response body
       (the balance) would be readable by the attacker's page.
    5. Confirm success: GET /flag with header Origin: null -- same
       allow-list logic /api/wallet uses, solved only once a literal
       "null" Origin comes back reflected with credentials allowed.

Fix: never special-case the literal string "null" (or any unvalidated
value) in a CORS allow-list -- it is not proof of same-machine local
testing, it is a value any attacker-controlled sandboxed iframe or data:
URI can produce from a real victim's browser. Drop the branch, or gate
local development behind an environment flag that never ships.
"""

import hashlib
import re

from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-76-cors-null-origin-bypass").hexdigest()[:16]

ALLOWED_ORIGIN_RE = re.compile(r"^https://partner-[a-z]+\.nullock-corp\.test$")


def _cors_allowed(origin):
    if not origin:
        return False
    # VULN: "null" is trusted alongside the real partner allow-list -- but
    # "null" is not proof of local testing, it's a string an attacker's
    # sandboxed iframe or data: URI can send from a real victim's browser.
    if origin == "null":
        return True
    return bool(ALLOWED_ORIGIN_RE.match(origin))


def _cors_response(body):
    resp = jsonify(body)
    origin = request.headers.get("Origin", "")
    if _cors_allowed(origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/")
def index():
    return (
        'wallet balance at <a href="/api/wallet">/api/wallet</a><br>'
        "try: Origin: https://attacker.example (blocked) vs Origin: null (allowed)"
    )


@app.route("/api/wallet")
def wallet():
    return _cors_response({"user": "alice", "balance_usd": 48213.02})


@app.route("/flag")
def flag():
    origin = request.headers.get("Origin", "")
    if origin != "null":
        return jsonify(solved=False, reason="send Origin: null, not a real hostname"), 400
    resp = _cors_response({"user": "alice", "balance_usd": 48213.02})
    if (resp.headers.get("Access-Control-Allow-Origin") == "null" and
            resp.headers.get("Access-Control-Allow-Credentials") == "true"):
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5076, debug=False)
