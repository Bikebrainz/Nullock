"""
Lab 22 -- Unrestricted file upload -> stored XSS.

/upload saves the uploaded file under uploads/ using the client-supplied
name with no type/content check, and /uploads/<name> serves it back with a
guessed content-type. Upload an .html (or .svg) carrying <script> and you
have stored XSS; the unsanitized name is also a traversal risk on save.

In Nullock:
    1. nullock scope add http://localhost:5022/*
    2. POST /upload a file 'x.html' containing <script>alert(1)</script>
    3. Browse /uploads/x.html -- the script executes (stored XSS).
    4. Confirm success: GET /flag?name=x.html -- solved only if that stored
       file both carries a browser-executable content-type (html/svg) and
       still contains the payload, proving it would actually run.

Fix: allow-list extensions/content-types, store outside the web root,
serve uploads with Content-Disposition: attachment and a fixed benign
content-type, and randomize the stored name (werkzeug.secure_filename).
"""

from flask import Flask, request, send_from_directory, jsonify
import hashlib
import mimetypes
import os

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-22-file-upload").hexdigest()[:16]
UP = os.path.join(os.path.dirname(__file__), "uploads")


@app.route("/", methods=["GET"])
def index():
    return ('<form method="post" action="/upload" enctype="multipart/form-data">'
            '<input type="file" name="f"><button>upload</button></form>')


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("f")
    if not f:
        return "no file", 400
    os.makedirs(UP, exist_ok=True)
    # VULN: trust the client filename; no type/content check.
    f.save(os.path.join(UP, f.filename))
    return "stored at /uploads/" + f.filename


@app.route("/uploads/<path:name>")
def serve(name):
    return send_from_directory(UP, name)   # served with a guessed content-type


@app.route("/flag")
def flag_route():
    # Solved only if the uploaded file both resolves inside uploads/ (no
    # traversal) and would actually execute: its guessed content-type is
    # browser-renderable (html/svg) AND it still carries a script payload.
    name = request.args.get("name", "")
    path = os.path.join(UP, os.path.basename(name)) if name else ""
    if not path or not os.path.isfile(path):
        return jsonify(solved=False), 403
    ctype, _ = mimetypes.guess_type(path)
    with open(path, "rb") as fh:
        body = fh.read()
    if ctype in ("text/html", "image/svg+xml") and b"<script" in body.lower():
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5022, debug=False)
