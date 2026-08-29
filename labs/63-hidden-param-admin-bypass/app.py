"""
Lab 63 -- A hidden parameter unlocks the admin panel, found only by parameter mining.

/admin is a real access-controlled endpoint: with no session and no special
input it returns 403 Forbidden, and nothing else on the site -- the index
page, its JS, robots.txt -- ever mentions any extra parameter for it. That's
deliberate: this isn't a documented feature with a link a crawler would find,
it's a leftover internal QA switch. Whoever wired it up left a `bypass`
query parameter in the handler that skips the auth check entirely whenever
it's present, no matter what value it carries. A spider or a manual read of
every page on the site will never surface it, because it was never written
down or linked anywhere -- only an active parameter-name brute-force
(Nullock's param miner) that watches for a STATUS FLIP relative to the 403
baseline will ever turn it up.

In Nullock:
    1. nullock scope add http://localhost:5063/*
    2. Crawl the site (Discover) and browse /admin directly: 403 Forbidden,
       every time, and there is nothing in the index page or its JS hinting
       at any extra parameter -- read-only reconnaissance dead-ends here.
    3. Run the parameter miner against GET /admin (SCANS tab's Assess &
       audit section -> param-miner, or POST /api/paramminer {"url":
       "http://localhost:5063/admin"}). It sends its built-in wordlist as
       isolated candidate query parameters, one at a time inside batches,
       each with a unique canary value, and isolates any name whose response
       STATUS differs from the 403 baseline.
    4. The miner reports "bypass" as the one candidate that flips the status
       to 200 -- the handler doesn't check the value, only that the
       parameter is present and non-empty.
    5. Confirm by hand: GET /admin?bypass=1 returns 200 with the admin
       panel's JSON, flag included.
    6. Fix: delete the leftover bypass switch before shipping -- a
       debug/QA-only override has no place in a production auth check, and
       access control must never key off the mere PRESENCE of a
       client-supplied parameter.
"""

import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-63-hidden-param-admin-bypass").hexdigest()[:16]


@app.route("/")
def index():
    return "Internal ops console. Most of it needs a login we haven't built yet."


@app.route("/admin")
def admin():
    # VULN: a leftover QA bypass -- presence of ANY non-empty "bypass" query
    # param skips the auth check entirely. Never linked, never documented,
    # invisible to a crawler; only parameter-name mining finds it.
    if request.args.get("bypass"):
        return jsonify(panel="admin", flag=FLAG)
    return jsonify(error="forbidden"), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5063, debug=False)
