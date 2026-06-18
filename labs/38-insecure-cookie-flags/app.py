"""
Lab 38 -- Insecure cookie flags.

/ sets a session cookie with NO HttpOnly, Secure, or SameSite attributes --
so it's readable by JavaScript (XSS -> session theft), sent over plaintext
HTTP (sniffing), and attached cross-site (CSRF).

In Nullock:
    1. nullock scope ... add http://localhost:5038/*
    2. nullock headeraudit http://localhost:5038/
       -- raises cookie-insecure (missing HttpOnly / Secure / SameSite).

Fix: set HttpOnly + Secure + SameSite=Lax/Strict on session cookies.
"""

from flask import Flask, make_response
import secrets

app = Flask(__name__)


@app.route("/")
def index():
    resp = make_response("<h1>home</h1>")
    # VULN: no HttpOnly / Secure / SameSite attributes.
    resp.set_cookie("session", secrets.token_hex(8))
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5038, debug=False)
