"""
Lab 22 -- Unrestricted file upload -> stored XSS.

/upload saves the uploaded file under uploads/ using the client-supplied
name with no type/content check, and /uploads/<name> serves it back with a
guessed content-type. Upload an .html (or .svg) carrying <script> and you
have stored XSS; the unsanitized name is also a traversal risk on save.

In Nullock:
    1. nullock scope ... add http://localhost:5022/*
    2. POST /upload a file 'x.html' containing <script>alert(1)</script>
    3. Browse /uploads/x.html -- the script executes (stored XSS).

Fix: allow-list extensions/content-types, store outside the web root,
serve uploads with Content-Disposition: attachment and a fixed benign
content-type, and randomize the stored name (werkzeug.secure_filename).
"""

from flask import Flask, request, send_from_directory
import os

app = Flask(__name__)
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5022, debug=False)
