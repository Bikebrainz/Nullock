"""
Lab 42 -- Sensitive data in the URL (credentials/token in query string).

/login takes the password as a GET query parameter, so it lands in browser
history, server access logs, and the Referer header sent to any third-party
resource the page loads.

In Nullock:
    1. nullock scope ... add http://localhost:5042/*
    2. GET /login?user=alice&password=hunter2 -- works, but the password is
       now in the URL (history / logs / Referer leakage).
    3. Note the welcome page loads an off-site image, leaking the full URL
       (with the password) via the Referer header.

Fix: accept credentials only via POST body over HTTPS; never put secrets in
URLs; set Referrer-Policy: no-referrer on sensitive pages.
"""

from flask import Flask, request

app = Flask(__name__)


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
        # off-site resource -> full URL (with password) leaks via Referer
        return '<h1>welcome</h1><img src="https://example.com/pixel.png">'
    return "bad credentials", 401


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5042, debug=False)
