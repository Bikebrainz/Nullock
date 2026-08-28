"""
Lab 56 -- Cross-site WebSocket hijacking (CSWSH) on a notifications feed.

The private notifications WebSocket authenticates the caller with a
`session` cookie -- the ambient credential a browser attaches on every
same-origin AND cross-origin request/handshake alike -- but never checks
the handshake's `Origin` header. Any page, on any origin, that gets a
logged-in victim's browser to open a WebSocket to this endpoint rides the
victim's session cookie in and receives their private notification feed:
CWE-1385, the same class Nullock's active `cswsh` probe fingerprints.

Run:
    pip install flask flask-sock
    python app.py

In Nullock:
    1. nullock scope add http://localhost:5056/*
    2. POST /login (form field "user", default alice) -- note the
       Set-Cookie: session=... in the response
       (curl -i -X POST -d user=alice http://127.0.0.1:5056/login).
    3. POST /api/cswsh/test { "url": "ws://127.0.0.1:5056/notifications/ws",
       "origin": "https://nullock-cswsh.test", "headers":
       {"Cookie": "session=<the cookie from step 2>"} } -- a foreign Origin
       Nullock made up, never one this app owns.
    4. The handshake completes (101 + valid Sec-WebSocket-Accept) despite
       the foreign Origin. Nullock then re-issues the SAME handshake with
       the Cookie stripped: that one gets refused (401, no upgrade at
       all) -- proving the socket actually gates on the session rather
       than being a public feed -- and grades the finding CONFIRMED
       (`vulnerable: true`), not just an Origin-not-validated lead.
    5. Confirm success: GET /flag with that same session cookie -- solved
       only once this lab's own WS server has recorded a completed
       upgrade that carried a valid session cookie alongside a foreign
       (non-app-origin) Origin header, i.e. an actual cross-origin
       hijack, not merely typing the flag text in.

Fix: validate `Origin` on every WebSocket upgrade against an allow-list of
the app's own origins -- refuse the handshake itself (before upgrading,
never accept-then-disconnect) -- in addition to the session-cookie check.
Better still, don't rely on ambient cookies to authenticate a WebSocket at
all: pass a short-lived, per-connection token in the handshake URL or
first message instead, the same principle a CSRF token applies to forms.
"""

import hashlib
import secrets

from flask import Flask, jsonify, make_response, request
from flask_sock import Sock

app = Flask(__name__)
sock = Sock(app)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-56-cswsh-notifications").hexdigest()[:16]

SESSIONS = {}   # session token -> username
APP_ORIGINS = {"http://localhost:5056", "http://127.0.0.1:5056"}
_hijacked = False   # set once a real cross-origin, credentialed upgrade completes

NOTIFICATIONS = {
    "alice": ["Your balance is $18,204.11", "New login from Kyiv, UA"],
}


@app.route("/")
def index():
    return ('<form action="/login" method="post">'
            '<input name="user" value="alice"><button>log in</button></form>')


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user", "alice")
    SESSIONS.setdefault(user, None)
    token = secrets.token_hex(16)
    SESSIONS[token] = user
    resp = make_response(jsonify(ok=True, user=user))
    resp.set_cookie("session", token, httponly=True)
    return resp


@app.before_request
def _gate_ws_upgrade():
    # flask-sock performs the WebSocket handshake -- sending the 101 --
    # the instant its view function starts running, so the ONLY place a
    # missing/invalid session can still produce a real refusal (rather
    # than upgrade-then-disconnect, which a handshake-status probe can't
    # see) is here, before that view ever runs. A request with no valid
    # session cookie never gets upgraded at all: a plain 401.
    if request.path == "/notifications/ws" and request.cookies.get("session") not in SESSIONS:
        return jsonify(error="login required"), 401


@sock.route("/notifications/ws")
def notifications_ws(ws):
    global _hijacked
    user = SESSIONS[request.cookies.get("session")]   # before_request proved this exists
    origin = request.headers.get("Origin", "")
    # VULN: Origin is read here only to decide whether THIS connection
    # counts as a cross-origin hijack for the flag below -- it is never
    # used to refuse the handshake, which is the actual bug: the socket
    # accepts every Origin as long as the session cookie is valid.
    if origin and origin not in APP_ORIGINS:
        _hijacked = True
    try:
        for note in NOTIFICATIONS.get(user, []):
            ws.send(note)
    except Exception:
        pass   # the probe closes right after the handshake; that's fine


@app.route("/flag")
def flag_route():
    if _hijacked and request.cookies.get("session") in SESSIONS:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5056, debug=False)
