"""
Lab 38 -- Insecure cookie flags.

/ sets a session cookie with NO HttpOnly, Secure, or SameSite attributes --
so it's readable by JavaScript (XSS -> session theft), sent over plaintext
HTTP (sniffing), and attached cross-site (CSRF).

In Nullock:
    1. nullock scope add http://localhost:5038/*
    2. nullock headeraudit http://localhost:5038/
       -- raises cookie-insecure (missing HttpOnly / Secure / SameSite).
    3. Confirm success: GET / and read the raw Set-Cookie value off the
       wire (readable because HttpOnly is absent -- a real attacker would
       read it via document.cookie after an XSS), then
       GET /flag?cookie=<that value> -- solved only for a value that was
       genuinely issued by the server.

Fix: set HttpOnly + Secure + SameSite=Lax/Strict on session cookies.
"""

from flask import Flask, make_response, request, jsonify
import hashlib
import secrets

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-38-insecure-cookie-flags").hexdigest()[:16]
ISSUED_COOKIES = set()


@app.route("/")
def index():
    resp = make_response("<h1>home</h1>")
    # VULN: no HttpOnly / Secure / SameSite attributes.
    val = secrets.token_hex(8)
    ISSUED_COOKIES.add(val)
    resp.set_cookie("session", val)
    return resp


@app.route("/flag")
def flag_route():
    v = request.args.get("cookie", "")
    if v and v in ISSUED_COOKIES:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5038, debug=False)
