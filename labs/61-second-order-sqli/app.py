"""
Lab 61 -- Second-order SQL injection via a reused username.

Registration is safe: the username you submit is stored with a
parameterized INSERT, so a `'` in it can't break that query. The
change-password feature is the trap: it looks up your username from the
database (not from the request) and then builds its UPDATE with
old-fashioned string formatting instead of a bound parameter. A payload
that did nothing on the way in (registration) detonates later, in a
completely different query, once the stored value is reused unsafely --
the defining trait of second-order (a.k.a. stored/second-round) SQLi.

In Nullock:
    1. nullock scope add http://localhost:5061/*
    2. Nullock's `sqli` active probe sends its payloads straight at each
       request's own parameters and grades the immediate response --
       it has nothing to inject here: /register and /change-password
       both take entirely benign-looking values on every single request
       you can throw at them directly. Run the probe against both and it
       reports clean. This is a genuine, honest blind spot: catching a
       payload that is inert in the request that carries it and only
       fires several requests and one stored round-trip later needs a
       multi-step, data-flow-aware tester, not a single-shot active
       probe. Manual testing (or Sequencer-style flow replay) is what
       finds this class -- exactly what this lab is for.
    3. Register a normal account (say, `mallory` / `pw1`) and log in --
       via Repeater, watch /change-password's own behavior with a
       harmless new password first, to see it succeeds for your own row.
    4. Register a SECOND account whose username is the payload:
       `administrator'--` / any password. Nullock's Inspector shows the
       raw response: registration succeeds and never reflects the
       username anywhere, because the INSERT is parameterized -- nothing
       to see yet.
    5. Log in as `administrator'--` and POST /change-password with
       {"new_password": "pwned123"}. The handler fetches your OWN
       username back out of the database and splices it into
       `UPDATE users SET password='...' WHERE username='<username>'`.
       With `username = administrator'--`, the trailing quote is
       commented out and the WHERE clause silently becomes
       `WHERE username='administrator'` -- you just changed the REAL
       administrator's password, not your own.
    6. Log in as `administrator` / `pwned123` and GET /flag.

Fix: parameterize EVERY query with a value that can carry attacker input,
no matter where that value came from -- including values the application
itself already stored. "It was safely inserted once" is not "safe to
concatenate forever after."
"""

import hashlib
import sqlite3
from flask import Flask, request, session, jsonify

app = Flask(__name__)
app.secret_key = "lab61-not-secret"
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-61-second-order-sqli").hexdigest()[:16]

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
db.execute("INSERT INTO users (username, password) VALUES ('administrator', ?)",
           (hashlib.sha256(b"correct-horse-battery-staple").hexdigest(),))
db.commit()


def pwhash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


@app.route("/")
def index():
    return '<a href="/register">register</a> / <a href="/login">log in</a>'


@app.route("/register", methods=["POST"])
def register():
    body = request.get_json(silent=True) or {}
    username, password = body.get("username", ""), body.get("password", "")
    if not username or not password:
        return jsonify(error="username and password required"), 400
    # SAFE: bound parameters -- a `'` in username can't break this INSERT.
    cur = db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, pwhash(password)))
    db.commit()
    return jsonify(ok=True, id=cur.lastrowid)


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    username, password = body.get("username", ""), body.get("password", "")
    # SAFE: bound parameters here too.
    row = db.execute("SELECT id FROM users WHERE username = ? AND password = ?",
                      (username, pwhash(password))).fetchone()
    if not row:
        return jsonify(error="invalid credentials"), 401
    session["uid"] = row[0]
    return jsonify(ok=True)


@app.route("/change-password", methods=["POST"])
def change_password():
    if "uid" not in session:
        return jsonify(error="log in first"), 401
    body = request.get_json(silent=True) or {}
    new_password = body.get("new_password", "")
    if not new_password:
        return jsonify(error="new_password required"), 400
    # The username itself is fetched safely...
    username = db.execute("SELECT username FROM users WHERE id = ?",
                           (session["uid"],)).fetchone()[0]
    # ...then VULN: spliced into the UPDATE with string formatting instead
    # of a bound parameter. A username stored earlier via the (safe)
    # /register INSERT can still carry a `'` straight into this WHERE
    # clause -- that's second-order injection.
    db.execute("UPDATE users SET password = '%s' WHERE username = '%s'" %
               (pwhash(new_password), username))
    db.commit()
    return jsonify(ok=True)


@app.route("/flag")
def flag_route():
    if "uid" not in session:
        return jsonify(solved=False, reason="log in first"), 403
    row = db.execute("SELECT username FROM users WHERE id = ?", (session["uid"],)).fetchone()
    if not row or row[0] != "administrator":
        return jsonify(solved=False,
                        reason="log in AS administrator (see walkthrough step 6)"), 403
    return jsonify(solved=True, flag=FLAG)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5061, debug=False)
