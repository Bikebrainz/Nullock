"""
Lab 21 -- Session fixation.

The app tracks sessions with a custom `sid` cookie and does NOT rotate it
on login. An attacker who plants a known `sid` in the victim's browser
(via a link/script) ends up authenticated as the victim once they log in.

In Nullock:
    1. nullock scope add http://localhost:5021/*
    2. GET / -- note the `sid` the server assigns.
    3. In Repeater, POST /login carrying that same `sid` -- after login the
       SAME `sid` is authenticated (no rotation). GET /whoami with it.
    4. So a pre-planted `sid` survives the privilege change.
    5. Confirm success: GET /flag with the SAME `sid` cookie used in steps
       2-3 -- only a sid that was already known BEFORE login, and is now
       authenticated, proves the fixation actually worked.

Fix: generate a fresh session id on every login (and privilege change).
"""

from flask import Flask, request, make_response, jsonify
import hashlib
import secrets

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-21-session-fixation").hexdigest()[:16]
SESSIONS = {}       # sid -> {"user": ...}
PRE_LOGIN_SIDS = set()   # sids handed out by index() BEFORE any login


@app.route("/")
def index():
    sid = request.cookies.get("sid")
    if not sid:
        sid = secrets.token_hex(8)
        SESSIONS.setdefault(sid, {})
    PRE_LOGIN_SIDS.add(sid)
    resp = make_response("your sid: " + sid)
    resp.set_cookie("sid", sid)
    return resp


@app.route("/login", methods=["POST"])
def login():
    sid = request.cookies.get("sid") or secrets.token_hex(8)
    # VULN: authenticate the EXISTING sid; never rotate it.
    SESSIONS[sid] = {"user": request.form.get("user", "alice")}
    resp = make_response("logged in; sid still " + sid)
    resp.set_cookie("sid", sid)
    return resp


@app.route("/whoami")
def whoami():
    return str(SESSIONS.get(request.cookies.get("sid", ""), {}))


@app.route("/flag")
def flag_route():
    # Solved only by a sid that was already known (via index()) BEFORE the
    # /login call that authenticated it -- proving the server never rotated
    # a pre-existing, potentially attacker-planted, session id.
    sid = request.cookies.get("sid", "")
    if sid and sid in PRE_LOGIN_SIDS and SESSIONS.get(sid, {}).get("user"):
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5021, debug=False)
