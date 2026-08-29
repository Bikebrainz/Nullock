"""
Lab 64 -- SSRF blocklist bypass via a same-app HTTP redirect.

/fetch?url=... blocks any URL whose STRING contains "127.0.0.1",
"169.254.169.254", or "/internal" -- a naive substring blocklist plenty of
real apps ship. It only ever inspects the URL the client submitted; it
never looks at where the outbound request actually ends up, and `requests`
follows redirects by default. So the blocklist stops a direct hit but does
nothing once a redirect is involved.

The app also exposes an innocuous-looking /goto?b64=<base64> link
redirector (think a "share this link" / URL-shortener feature that nobody
thought to connect to the SSRF fix). Base64-encoding the real target hides
the blocked substrings from /fetch's filter; /fetch happily requests
/goto, which 302s straight at the forbidden 127.0.0.1 /internal endpoint,
and the outbound client silently follows it there.

In Nullock:
    1. nullock scope add http://localhost:5064/*
    2. /fetch?url=http://127.0.0.1:5064/internal -- 400 "blocked host":
       the naive filter works against a direct hit.
    3. Base64-encode the real target yourself (or note the one below) and
       request /fetch?url=http://localhost:5064/goto?b64=<that> instead --
       200, the internal secret comes back. The blocklist never saw
       "127.0.0.1" or "/internal" anywhere in the URL it checked.
    4. Confirm success: GET /flag -- solved only once /fetch's own
       outbound request followed the redirect and read the internal
       secret back (browsing /internal directly does not solve it -- the
       point is the SSRF pivot through /fetch, not the endpoint existing).

Fix: validate the FINAL destination after following every redirect (or set
allow_redirects=False and re-check each hop yourself) -- never trust a
blocklist that only ever looks at the string the client sent.

(Needs `requests`, like the labs' other SSRF entries.)
"""

import base64
import hashlib

import requests
from flask import Flask, jsonify, redirect, request

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-64-ssrf-redirect-bypass").hexdigest()[:16]
SSRF_HIT = {"done": False}
BLOCKED_SUBSTRINGS = ("127.0.0.1", "169.254.169.254", "/internal")


@app.route("/")
def index():
    demo = base64.b64encode(b"http://127.0.0.1:5064/internal").decode()
    return (
        '<a href="/fetch?url=http://example.com/">fetch a URL</a><br>'
        "blocked direct hit: /fetch?url=http://127.0.0.1:5064/internal<br>"
        "redirect bypass: /fetch?url=http://localhost:5064/goto?b64=%s" % demo
    )


@app.route("/goto")
def goto():
    # VULN half 2: decode and 302 wherever the blob points -- no
    # validation, on the assumption /fetch already validated the URL.
    try:
        target = base64.b64decode(request.args.get("b64", "")).decode()
    except Exception:
        return "bad b64", 400
    return redirect(target, code=302)


@app.route("/internal")
def internal():
    # Intended to be internal-only; reachable only via the /fetch pivot.
    return "INTERNAL SECRET: db_password=hunter2"


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="missing url"), 400
    # VULN half 1: the blocklist only inspects the literal string the
    # client sent -- never the final destination a redirect lands on.
    if any(b in url for b in BLOCKED_SUBSTRINGS):
        return jsonify(error="blocked host"), 400
    try:
        r = requests.get(url, timeout=3)  # allow_redirects=True by default
    except requests.RequestException as e:
        return jsonify(error=str(e)), 502
    if "INTERNAL SECRET" in r.text:
        SSRF_HIT["done"] = True
    return (r.text, r.status_code, {"Content-Type": "text/plain"})


@app.route("/flag")
def flag():
    if SSRF_HIT["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5064, debug=False)
