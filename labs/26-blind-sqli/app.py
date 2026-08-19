"""
Lab 26 -- Blind (boolean-based) SQL injection.

/product?id=... concatenates id into a SQLite query. There's no error
output, but the response differs when the injected condition is true vs
false ("in stock" vs "no such product"), so data leaks one bit at a time.

In Nullock:
    1. nullock scope add http://localhost:5026/*
    2. Send /product?id=1 to Repeater.
    3. id=1 AND 1=1  -> shown;  id=1 AND 1=2 -> not shown (boolean oracle).
    4. Automate with Intruder, e.g.
         id=1 AND substr((SELECT password FROM users LIMIT 1),1,1)='s'
    5. Confirm success: GET /flag?password=<extracted password> -- solved
       only by submitting the actual admin password extracted bit by bit,
       never visible through the legitimate /product?id= path.

Fix: use parameterized queries; never string-concatenate SQL.
"""

from flask import Flask, request, jsonify
import hashlib
import sqlite3

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-26-blind-sqli").hexdigest()[:16]
ADMIN_PASSWORD = "s3cr3t"


def db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE products(id INTEGER, name TEXT)")
    c.execute("INSERT INTO products VALUES (1,'widget'),(2,'gadget')")
    c.execute("CREATE TABLE users(username TEXT, password TEXT)")
    c.execute("INSERT INTO users VALUES ('admin','s3cr3t')")
    return c


@app.route("/")
def index():
    return '<a href="/product?id=1">view product 1</a>'


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    conn = db()
    try:
        # VULN: id concatenated into the query.
        rows = conn.execute("SELECT name FROM products WHERE id = " + pid).fetchall()
    except sqlite3.Error:
        rows = []   # blind: errors swallowed -- only the boolean leaks
    return ("in stock: " + rows[0][0]) if rows else "no such product"


@app.route("/flag")
def flag_route():
    if request.args.get("password", "") == ADMIN_PASSWORD:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5026, debug=False)
