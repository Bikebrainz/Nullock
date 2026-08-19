"""
Lab 39 -- Missing security headers.

/ serves an app with NO Content-Security-Policy, Strict-Transport-Security,
or X-Content-Type-Options -- leaving it open to XSS escalation, TLS
stripping, and MIME sniffing.

In Nullock:
    1. nullock scope add http://localhost:5039/*
    2. nullock headeraudit http://localhost:5039/
       -- raises csp-missing, xcto-missing, clickjacking-missing (and more).
       Note: hsts-missing does NOT fire here -- that check only applies to
       an https response, and this lab deliberately runs over plain http.
    3. Confirm success: GET /flag?findings=csp-missing,xcto-missing --
       solved only after visiting / and naming findings that genuinely
       fire on this plain-http response (submitting hsts-missing, which
       can never fire here, fails the check).

Fix: send Content-Security-Policy, Strict-Transport-Security (long max-age +
includeSubDomains), and X-Content-Type-Options: nosniff on every response.
"""

from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-39-missing-security-headers").hexdigest()[:16]
VISITED = {"seen": False}
REQUIRED_FINDINGS = {"csp-missing", "xcto-missing"}
IMPOSSIBLE_OVER_HTTP = {"hsts-missing", "hsts-invalid", "hsts-disabled", "hsts-weak", "hsts-no-subdomains"}


@app.route("/")
def index():
    # VULN: no security headers set at all.
    VISITED["seen"] = True
    return "<h1>app</h1><p>no CSP / HSTS / nosniff here</p>"


@app.route("/flag")
def flag_route():
    submitted = set(x.strip() for x in request.args.get("findings", "").split(",") if x.strip())
    if VISITED["seen"] and REQUIRED_FINDINGS.issubset(submitted) and not (submitted & IMPOSSIBLE_OVER_HTTP):
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5039, debug=False)
