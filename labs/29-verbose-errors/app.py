"""
Lab 29 -- Information disclosure via verbose errors.

/calc?n=... parses input and, on failure, returns the full Python exception
traceback -- leaking file paths, the framework version, and internal types
an attacker can use to tailor the next step.

In Nullock:
    1. nullock scope add http://localhost:5029/*
    2. /calc?n=21    -> 42
    3. /calc?n=oops  -> a stack trace with absolute paths is returned.
    4. Confirm success: GET /flag?path=<a fragment of the leaked absolute
       path> -- solved only by submitting a piece of the real path the
       traceback exposed, never shown on the happy path.

Fix: log details server-side, return a generic error to the client, and
never run debug mode / ship stack traces in production.
"""

from flask import Flask, request, jsonify
import hashlib
import os
import traceback

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-29-verbose-errors").hexdigest()[:16]


@app.route("/")
def index():
    return '<a href="/calc?n=21">calc</a>'


@app.route("/calc")
def calc():
    n = request.args.get("n", "0")
    try:
        return str(int(n) * 2)
    except Exception:
        # VULN: full traceback returned to the client.
        return "<pre>" + traceback.format_exc() + "</pre>", 500


@app.route("/flag")
def flag_route():
    # The traceback's frame for this file includes its absolute path, whose
    # directory name is never shown anywhere else in the app -- submitting
    # a fragment containing it proves the leak was actually read.
    leaked = request.args.get("path", "")
    real_dir = os.path.basename(os.path.dirname(os.path.abspath(__file__)))
    if leaked and real_dir in leaked:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5029, debug=False)
