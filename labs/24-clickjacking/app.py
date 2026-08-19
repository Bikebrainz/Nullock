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
    4. PoC: browse /decoy -- an attacker page with <iframe src=.../dashboard>
       overlaid beneath a decoy "claim your prize" button; the disguised
       click actually submits the hidden Delete-account form underneath.
    5. Confirm success: GET /flag -- solved only once a delete request has
       actually landed with a Referer proving it was framed inside /decoy.

Fix: send Content-Security-Policy: frame-ancestors 'none' (or 'self'),
with X-Frame-Options: DENY as a fallback.
"""

from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-24-clickjacking").hexdigest()[:16]
STATE = {"deleted_via_frame": False}


@app.route("/")
def index():
    return '<a href="/dashboard">dashboard</a>'


@app.route("/dashboard")
def dashboard():
    # VULN: no X-Frame-Options / CSP frame-ancestors -- framable.
    return ('<h1>Account dashboard</h1>'
            '<form method="post" action="/dashboard/delete">'
            '<button>Delete account</button></form>')


@app.route("/decoy")
def decoy():
    # Attacker's page: a near-invisible iframe over /dashboard, with a
    # decoy button positioned right over the real Delete button beneath.
    return ('<style>iframe{opacity:0.001;position:absolute;top:0;left:0;'
            'width:400px;height:200px;border:0}'
            'button.decoy{position:absolute;top:60px;left:140px}</style>'
            '<button class="decoy">Claim your prize!</button>'
            '<iframe src="/dashboard"></iframe>')


@app.route("/dashboard/delete", methods=["POST"])
def dashboard_delete():
    # Only a click routed through the framed /decoy page (Referer proves
    # the browser was navigating inside that page's iframe) counts as the
    # clickjacked action; a direct same-page click is not the exploit.
    if "/decoy" in request.headers.get("Referer", ""):
        STATE["deleted_via_frame"] = True
        return "account deleted (simulated)"
    return "blocked: not a framed click", 403


@app.route("/flag")
def flag_route():
    if STATE["deleted_via_frame"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5024, debug=False)
