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

Fix: disable DTDs / external entities in the parser (defusedxml, or
libxml2 with no_network + resolve_entities off). Never resolve entities
from untrusted XML.

(The resolver below is a deliberately minimal stand-in for a misconfigured
real parser -- it honors `<!ENTITY x SYSTEM "file://...">` exactly as
libxml2 would with entity resolution left on, so the bug is faithful while
the lab stays dependency-free.)
"""

from flask import Flask, request, Response
from urllib.parse import urlparse, unquote
import os
import re

app = Flask(__name__)

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
        body = body.replace("&%s;" % name, _read_file_uri(uri))
    return Response(body, mimetype="application/xml")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5043, debug=False)
