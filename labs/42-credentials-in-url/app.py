"""
Lab 42 -- Sensitive data in the URL (credentials/token in query string).

/login takes the password as a GET query parameter, so it lands in browser
history, server access logs, and the Referer header sent to any third-party
resource the page loads.

In Nullock:
    1. nullock scope add http://localhost:5042/*
    2. GET /login?user=alice&password=hunter2 -- works, but the password is
       now in the URL (history / logs / Referer leakage).
    3. Note the welcome page loads an off-site pixel image, leaking the full
       URL (with the password) via the Referer header.
    4. Confirm success: GET /pixel.png with a Referer header set to the exact
       login URL used in step 2 (a real browser would send this on its own;
       here it's simulated by hand), then GET /flag -- solved only once the
       password was proven to leak via Referer to a third-party resource,
       not just that GET-based login worked.

Fix: accept credentials only via POST body over HTTPS; never put secrets in
URLs; set Referrer-Policy: no-referrer on sensitive pages.
"""

from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-42-credentials-in-url").hexdigest()[:16]
LOGGED_IN = {"done": False}
REFERER_LEAKED = {"done": False}


@app.route("/")
def index():
    return ('<form action="/login" method="get">'      # VULN: method=get
            '<input name="user" value="alice">'
            '<input name="password"><button>login</button></form>')


@app.route("/login")
def login():
    user = request.args.get("user", "")
    pw = request.args.get("password", "")              # VULN: secret in query string
    if user == "alice" and pw == "hunter2":
        LOGGED_IN["done"] = True
        # off-site resource -> full URL (with password) leaks via Referer
        return '<h1>welcome</h1><img src="/pixel.png">'
    return "bad credentials", 401


@app.route("/pixel.png")
def pixel():
    # Stand-in for a genuinely third-party resource (e.g. an ad/analytics
    # pixel on example.com): whatever loads this sees the full referring
    # URL, password and all, in the Referer header.
    referer = request.headers.get("Referer", "")
    if "password=hunter2" in referer:
        REFERER_LEAKED["done"] = True
    return "", 204


@app.route("/flag")
def flag_route():
    if LOGGED_IN["done"] and REFERER_LEAKED["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5042, debug=False)
