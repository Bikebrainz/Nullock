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

Fix: generate a fresh session id on every login (and privilege change).
"""

from flask import Flask, request, make_response
import secrets

app = Flask(__name__)
SESSIONS = {}   # sid -> {"user": ...}


@app.route("/")
def index():
    sid = request.cookies.get("sid")
    if not sid:
        sid = secrets.token_hex(8)
        SESSIONS.setdefault(sid, {})
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5021, debug=False)
