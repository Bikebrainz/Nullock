"""
Lab 43 -- XML External Entity (XXE) injection.

POST an XML document to / and the server "parses" it with external-entity
resolution enabled, so a SYSTEM entity pointing at a local file is expanded
into the response -- letting an attacker read arbitrary files off the host.

In Nullock:
    1. nullock scope add http://localhost:5043/*
    2. nullock xxe http://localhost:5043/
       -- POSTs an entity targeting /etc/passwd (or c:/windows/win.ini on
       Windows); Nullock confirms XXE when the file's content comes back.
    3. Confirm success: POST an XML document declaring
       `<!ENTITY x SYSTEM "file://<labdir>/secret.txt">` and referencing
       `&x;` in the body -- the app ships its own local secret.txt so the
       lab is self-contained (no OS-specific path needed). Then GET /flag
       -- solved only once that file's real, server-generated content came
       back in the response, proving the entity was actually resolved.

Fix: disable DTDs / external entities in the parser (defusedxml, or
libxml2 with no_network + resolve_entities off). Never resolve entities
from untrusted XML.

(The resolver below is a deliberately minimal stand-in for a misconfigured
real parser -- it honors `<!ENTITY x SYSTEM "file://...">` exactly as
libxml2 would with entity resolution left on, so the bug is faithful while
the lab stays dependency-free.)
"""

from flask import Flask, request, Response, jsonify
from urllib.parse import urlparse, unquote
import hashlib
import os
import re
import secrets

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-43-xxe").hexdigest()[:16]
SECRET_PATH = os.path.join(os.path.dirname(__file__), "secret.txt")
SECRET_MARKER = "xxe-proof-" + secrets.token_hex(8)
FILE_READ = {"done": False}

_ENTITY = re.compile(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>', re.IGNORECASE)


def _read_file_uri(uri):
    p = urlparse(uri)
    if p.scheme != "file":
        return ""                       # this stand-in only resolves file://
    path = unquote(p.path)
    if os.name == "nt" and re.match(r"^/[A-Za-z]:", path):
        path = path[1:]                 # /c:/windows/win.ini -> c:/windows/win.ini
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return ('<form method="post">POST an XML document here.</form>')
    body = request.get_data(as_text=True)
    # VULN: external entities declared in untrusted input are resolved.
    for name, uri in _ENTITY.findall(body):
        resolved = _read_file_uri(uri)
        if SECRET_MARKER in resolved:
            FILE_READ["done"] = True
        body = body.replace("&%s;" % name, resolved)
    return Response(body, mimetype="application/xml")


@app.route("/flag")
def flag_route():
    if FILE_READ["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "w") as fh:
            fh.write("internal only: %s\n" % SECRET_MARKER)
    app.run(host="127.0.0.1", port=5043, debug=False)
