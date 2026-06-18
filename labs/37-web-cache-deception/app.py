"""
Lab 37 -- Web cache deception.

/account returns the logged-in user's private data, and the app also serves
that same content under /account/<anything>.css (the suffix is ignored). A
CDN/proxy that caches by extension will store the victim's private page at a
static-looking URL the attacker can then fetch.

In Nullock:
    1. nullock scope add http://localhost:5037/*
    2. nullock cachedeception http://localhost:5037/account
       -- it probes /account/<rand>.css, sees the same private content with a
       cacheable response, and flags web-cache-deception.

Fix: don't serve dynamic content under static-looking paths; make the cache
honor Cache-Control (don't cache purely by extension); 404 unexpected
suffixes.
"""

from flask import Flask, Response

app = Flask(__name__)
ACCOUNT = "<h1>Account</h1><p>balance: $4,200 -- email: alice@corp.example</p>"


def page():
    r = Response(ACCOUNT)
    r.headers["Cache-Control"] = "public, max-age=300"   # VULN: private page cacheable
    return r


@app.route("/")
def index():
    return '<a href="/account">my account</a>'


@app.route("/account")
@app.route("/account/<path:ignored>")   # VULN: suffix ignored -> path confusion
def account(ignored=None):
    return page()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5037, debug=False)
