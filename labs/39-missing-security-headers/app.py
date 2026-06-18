"""
Lab 39 -- Missing security headers.

/ serves an app with NO Content-Security-Policy, Strict-Transport-Security,
or X-Content-Type-Options -- leaving it open to XSS escalation, TLS
stripping, and MIME sniffing.

In Nullock:
    1. nullock scope add http://localhost:5039/*
    2. nullock headeraudit http://localhost:5039/
       -- raises csp-missing, hsts-missing, xcto-missing (and more).

Fix: send Content-Security-Policy, Strict-Transport-Security (long max-age +
includeSubDomains), and X-Content-Type-Options: nosniff on every response.
"""

from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    # VULN: no security headers set at all.
    return "<h1>app</h1><p>no CSP / HSTS / nosniff here</p>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5039, debug=False)
