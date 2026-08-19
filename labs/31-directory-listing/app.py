"""
Lab 31 -- Directory listing / index disclosure.

/files (no specific file) returns an autoindex of the docroot -- file names
an attacker would never have guessed (backups, internal notes). /files/<name>
then serves any listed file.

In Nullock:
    1. nullock scope add http://localhost:5031/*
    2. Browse /files -- the listing reveals secret-notes.txt and backup.zip.
    3. Fetch /files/secret-notes.txt directly.
    4. Confirm success: GET /flag -- solved only once the listing was
       browsed AND secret-notes.txt was fetched afterward, proving the file
       was actually discovered via the index rather than blindly guessed.

Fix: disable autoindex; serve only an explicit allow-list; keep sensitive
files out of the web root.
"""

from flask import Flask, send_from_directory, jsonify
import hashlib
import os

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-31-directory-listing").hexdigest()[:16]
DOC = os.path.join(os.path.dirname(__file__), "docroot")
DISCOVERED = {"listing": False, "secret": False}


@app.route("/")
def index():
    return '<a href="/files">browse files</a>'


@app.route("/files")
@app.route("/files/")
def listing():
    # VULN: expose the directory index.
    DISCOVERED["listing"] = True
    links = "".join('<li><a href="/files/%s">%s</a></li>' % (n, n)
                    for n in sorted(os.listdir(DOC)))
    return "<h1>Index of /files</h1><ul>" + links + "</ul>"


@app.route("/files/<path:name>")
def getfile(name):
    if name == "secret-notes.txt" and DISCOVERED["listing"]:
        DISCOVERED["secret"] = True
    return send_from_directory(DOC, name)


@app.route("/flag")
def flag_route():
    if DISCOVERED["listing"] and DISCOVERED["secret"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    os.makedirs(DOC, exist_ok=True)
    seed = {"readme.txt": "public readme\n",
            "secret-notes.txt": "internal: admin password rotation TODO\n",
            "backup.zip": "(pretend backup archive)\n"}
    for n, c in seed.items():
        p = os.path.join(DOC, n)
        if not os.path.exists(p):
            with open(p, "w") as fh:
                fh.write(c)
    app.run(host="127.0.0.1", port=5031, debug=False)
