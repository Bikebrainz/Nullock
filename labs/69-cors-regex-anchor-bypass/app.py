"""
Lab 69 -- CORS allow-list bypass via an unanchored regex.

/api/account is a credentialed, session-cookie-authenticated endpoint meant
to be callable cross-origin only by the bank's own partner frontend,
https://partner.nullock.test (and its subdomains, e.g. a staging
environment). The allow-list check uses a regex that anchors the START of
the Origin string but never anchors the END:

    re.match(r'^https://([\\w-]+\\.)*partner\\.nullock\\.test', origin)

`re.match` only requires the pattern to match a PREFIX of the string, not
the whole thing -- and there is no trailing `$`. So the regex matches not
only "https://partner.nullock.test" and "https://staging.partner.nullock.test"
but also "https://partner.nullock.test.attacker.test": an attacker who
controls attacker.test can create that exact subdomain, point it at a page
they host, and any browser that visits it will have `partner.nullock.test`
as a *prefix* of the real Origin header the browser sends -- which is all
this regex checks.

This is a different CORS bug from Lab 16 (blanket Origin reflection, no
allow-list at all). Here there IS an allow-list, and it correctly rejects
naive attempts like "https://evilpartner.nullock.test" (no dot separator,
so the literal "partner.nullock.test" substring never appears right after
the scheme) or "https://partner.nullock.test.evil.com" sent from an origin
you don't control. The only way through is a domain suffix trick: register
(or in this lab, simply claim) a hostname whose FIRST label sequence
literally reads "partner.nullock.test." followed by anything you own.

In Nullock:
    1. nullock scope add http://localhost:5069/*
    2. Send /api/account with header Origin: https://evil.example --
       rejected: no ACAO header at all (the naive reflect-everything bug
       from Lab 16 is NOT present here).
    3. Try Origin: https://evilpartner.nullock.test -- still rejected
       (the regex's ^ anchor plus literal "partner.nullock.test" means a
       prefix like "evil" glued directly onto "partner" doesn't match).
    4. Try Origin: https://partner.nullock.test.attacker.test -- ACCEPTED.
       ACAO reflects it, ACAC: true. The regex matched only the first
       ~35 characters of the Origin string and never checked there was
       nothing else after "test".
    5. Confirm success: GET /flag with that same Origin header -- the
       endpoint uses the identical (buggy) allow-list check, so it hands
       back the flag once it sees a cross-origin request the check should
       have rejected but didn't.

Fix: anchor the pattern at both ends (add `$`), or better, parse the
Origin's host with urllib.parse and compare it against an exact allow-list
of hostnames (equality or a real `.endswith("." + trusted)` check with the
leading-dot boundary, never a raw regex/substring match).
"""

import hashlib
import re
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-69-cors-regex-anchor-bypass").hexdigest()[:16]

# VULN: no trailing `$` -- re.match only requires this pattern to match a
# PREFIX of the Origin string, so anything can be appended after
# "partner.nullock.test" and still pass.
TRUSTED_ORIGIN_RE = re.compile(r"^https://([\w-]+\.)*partner\.nullock\.test")

ACCOUNT = {"user": "alice", "balance": 84213.50, "iban": "GB00NULL00000000000069"}


def _cors_allow(resp, origin):
    if origin and TRUSTED_ORIGIN_RE.match(origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
    return resp


@app.route("/api/account", methods=["GET", "OPTIONS"])
def account():
    origin = request.headers.get("Origin", "")
    resp = jsonify(ACCOUNT)
    return _cors_allow(resp, origin)


@app.route("/flag", methods=["GET", "OPTIONS"])
def flag():
    origin = request.headers.get("Origin", "")
    if not TRUSTED_ORIGIN_RE.match(origin):
        resp = jsonify(solved=False)
        return resp, 403
    # Confirm this is a genuine bypass, not just the real partner origin.
    if origin.rstrip("/") == "https://partner.nullock.test":
        resp = jsonify(solved=False, hint="that's the real partner origin -- find a host the regex wrongly trusts")
        return resp, 403
    resp = jsonify(solved=True, flag=FLAG)
    return _cors_allow(resp, origin)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5069, debug=False)
