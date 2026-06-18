"""
Lab 24 -- Clickjacking (missing frame protections).

/dashboard serves a sensitive, state-changing UI with NO X-Frame-Options
and NO Content-Security-Policy frame-ancestors -- so an attacker can frame
it transparently and trick the victim into clicking a hidden control
(UI redress).

In Nullock:
    1. nullock scope add http://localhost:5024/*
    2. Browse /dashboard -- captured.
    3. Run the header audit:  nullock headeraudit http://localhost:5024/dashboard
       It raises 'clickjacking-missing' (no XFO / frame-ancestors).
    4. PoC: an attacker page with <iframe src=.../dashboard> overlaid
       beneath a decoy button.

Fix: send Content-Security-Policy: frame-ancestors 'none' (or 'self'),
with X-Frame-Options: DENY as a fallback.
"""

from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return '<a href="/dashboard">dashboard</a>'


@app.route("/dashboard")
def dashboard():
    # VULN: no X-Frame-Options / CSP frame-ancestors -- framable.
    return '<h1>Account dashboard</h1><button>Delete account</button>'


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5024, debug=False)
