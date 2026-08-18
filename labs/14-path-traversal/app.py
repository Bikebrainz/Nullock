"""
Lab 14 -- Path traversal / LFI.

/download?file=... joins the name onto a base directory and returns the
file contents with no canonicalization, so '../' escapes the directory and
reads arbitrary files (e.g. /etc/passwd).

In Nullock:
    1. nullock scope add http://localhost:5014/*
    2. Browse http://localhost:5014/download?file=note.txt   (normal)
    3. Send to Repeater, set file to:  ../../../../etc/passwd
    4. The response leaks the file outside the base dir.
    5. Run the active probe (lfi): it confirms by the file's content
       fingerprint (line-anchored /etc/passwd or win.ini signature).
    6. Confirm success: GET /flag?file=../secret.txt -- same raw
       os.path.join /download uses, reading a marker file that lives
       one directory above BASE and was never linked from any page.

Fix: resolve the path (os.path.realpath) and verify it stays within the
base dir with a prefix check; never join user input onto a path raw.
"""

import hashlib
from flask import Flask, request, jsonify
import os

app = Flask(__name__)
BASE = os.path.join(os.path.dirname(__file__), "public")
SECRET_PATH = os.path.join(os.path.dirname(__file__), "secret.txt")
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-14-path-traversal").hexdigest()[:16]


@app.route("/")
def index():
    return '<a href="/download?file=note.txt">download note.txt</a>'


@app.route("/download")
def download():
    name = request.args.get("file", "note.txt")
    # VULN: no canonicalization -- '../' escapes BASE.
    path = os.path.join(BASE, name)
    try:
        with open(path, "r", errors="replace") as fh:
            return "<pre>" + fh.read() + "</pre>"
    except OSError:
        return "not found", 404


@app.route("/flag")
def flag():
    name = request.args.get("file", "note.txt")
    # Same raw os.path.join as /download.
    path = os.path.join(BASE, name)
    try:
        with open(path, "r", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return jsonify(solved=False), 404
    # Solved only when the resolved path actually escaped BASE and the
    # content matches the marker planted outside it -- not just any
    # readable file inside the public dir.
    escaped = not os.path.realpath(path).startswith(os.path.realpath(BASE) + os.sep)
    if escaped and "lab14-secret-marker" in content:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    os.makedirs(BASE, exist_ok=True)
    with open(os.path.join(BASE, "note.txt"), "w") as fh:
        fh.write("public note -- nothing secret here\n")
    with open(SECRET_PATH, "w") as fh:
        fh.write("lab14-secret-marker -- outside the public dir, unlinked\n")
    app.run(host="127.0.0.1", port=5014, debug=False)
