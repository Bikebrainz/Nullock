"""
Lab 02 -- Error-based SQL injection.

The /user endpoint builds a SQL query via string concatenation. A single
quote breaks the query and surfaces a SQLite stack trace -- enough
context for an attacker to extract data via UNION SELECT.

Run:
    pip install flask
    python app.py

In Nullock:
    1. Browse http://localhost:5002/user?id=1
    2. Send to Repeater
    3. Change id to: 1'
    4. Fire -- response contains "near \\"'\\": syntax error" -- SQLi error
       fragment. PassiveScanner should also raise a "sqli-error"
       finding for this row on its own.
    5. Extract: change id to: 1 UNION SELECT name||'/'||password FROM users
    6. Confirm success: GET /flag?id=<injection> -- the flag lives in the
       password column of a hidden admin row (id=99) that /user never
       serves through a legitimate numeric id. Pull it out with
       ?id=0 UNION SELECT password FROM users WHERE id=99 and the
       endpoint verifies it and hands back the flag.
"""

import hashlib, os, sqlite3, tempfile
from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-02-sqli-basic").hexdigest()[:16]

DB = os.path.join(tempfile.gettempdir(), "nullock-lab-02.db")

def init_db():
    if os.path.exists(DB):
        return
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)")
    cur.executemany("INSERT INTO users VALUES (?, ?, ?)", [
        (1, "alice", "wonderland"),
        (2, "bob",   "builder"),
        (3, "carol", "singer42"),
        # VULN target: never linked/listed, only reachable via SQLi.
        (99, "admin", FLAG),
    ])
    con.commit()
    con.close()

@app.route("/")
def index():
    return '<a href="/user?id=1">user 1</a>'

@app.route("/user")
def user():
    init_db()
    uid = request.args.get("id", "1")
    # VULN: string concat. Try ?id=1'
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute(f"SELECT name FROM users WHERE id = {uid}")
    row = cur.fetchone()
    con.close()
    if row is None:
        return "no user found", 404
    return f"<p>user: {row[0]}</p>"

@app.route("/flag")
def flag():
    init_db()
    uid = request.args.get("id", "1")
    # Same vulnerable concatenation as /user -- reused deliberately so
    # solving this route IS solving the lab, not a separate puzzle.
    con = sqlite3.connect(DB)
    cur = con.cursor()
    try:
        cur.execute(f"SELECT name FROM users WHERE id = {uid}")
        rows = cur.fetchall()
    except sqlite3.Error:
        rows = []
    con.close()
    leaked = {str(v) for row in rows for v in row}
    if FLAG in leaked:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
