"""
Lab 19 -- Cross-Site Request Forgery (CSRF).

POST /change-email updates the account email with NO anti-CSRF token, and
the session cookie has no SameSite attribute. Any malicious page the
victim visits can auto-submit this form using the victim's cookies.

In Nullock:
    1. nullock scope add http://localhost:5019/*
    2. POST /login (any user), then use /change-email -- captured.
    3. Note: no CSRF token in the request, and the session cookie has no
       SameSite attribute (the header audit flags the cookie).
    4. A cross-site auto-submitting form to /change-email succeeds.
    5. Confirm success: POST /flag (logged in first) with an Origin/
       Referer header for a different site, e.g. https://evil.example --
       simulating the forged cross-site form. Same no-token state change
       as /change-email; hands back the flag once it succeeds anyway.

Fix: require a per-session CSRF token on state-changing requests, and set
SameSite=Lax/Strict on the session cookie.
"""

import hashlib
from urllib.parse import urlparse
from flask import Flask, request, session, redirect, jsonify

app = Flask(__name__)
app.secret_key = "lab19-not-secret"
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-19-csrf").hexdigest()[:16]
EMAIL = {"value": "alice@corp.example"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        session["user"] = request.form.get("user", "alice")
        return redirect("/account")
    return '<form method="post"><input name="user" value="alice"><button>login</button></form>'


@app.route("/account")
def account():
    if "user" not in session:
        return redirect("/login")
    return ('email: ' + EMAIL["value"] +
            '<form method="post" action="/change-email">'
            '<input name="email"><button>change</button></form>')


@app.route("/change-email", methods=["POST"])
def change_email():
    if "user" not in session:
        return "login first", 401
    # VULN: state change with no CSRF token.
    EMAIL["value"] = request.form.get("email", "")
    return "email changed to " + EMAIL["value"]


@app.route("/flag", methods=["POST"])
def flag():
    if "user" not in session:
        return jsonify(solved=False, reason="login first via /login"), 401
    origin = request.headers.get("Origin") or request.headers.get("Referer") or ""
    own = urlparse(request.host_url).netloc
    forged = bool(urlparse(origin).netloc) and urlparse(origin).netloc != own
    if not forged:
        return jsonify(solved=False, reason="simulate a cross-site Origin/Referer header"), 403
    # Same no-token state change as /change-email -- proves the forged
    # cross-site request succeeds purely on the ambient session cookie.
    EMAIL["value"] = request.form.get("email", "pwned@evil.example")
    return jsonify(solved=True, flag=FLAG, email=EMAIL["value"])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5019, debug=False)
