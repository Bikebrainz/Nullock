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

Fix: resolve the path (os.path.realpath) and verify it stays within the
base dir with a prefix check; never join user input onto a path raw.
"""

from flask import Flask, request
import os

app = Flask(__name__)
BASE = os.path.join(os.path.dirname(__file__), "public")


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


if __name__ == "__main__":
    os.makedirs(BASE, exist_ok=True)
    with open(os.path.join(BASE, "note.txt"), "w") as fh:
        fh.write("public note -- nothing secret here\n")
    app.run(host="127.0.0.1", port=5014, debug=False)
