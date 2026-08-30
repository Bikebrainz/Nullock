"""
Lab 70 -- SSRF scheme bypass: a host blocklist that never checks the scheme.

/fetch?url=... is "protected" against SSRF: it parses the URL and rejects any
request whose HOST is 127.0.0.1, localhost, 169.254.169.254, or contains
"internal" -- the usual cloud-metadata/loopback blocklist. That check works
fine for http:// and https:// targets. But the fetcher itself isn't limited
to http(s) -- it uses urllib.request.urlopen(), which happily also handles
ftp://, data://, and file:// -- and a file:// URL has no network host at
all: urlparse("file:///etc/nullock-lab70-config").hostname is None. The
blocklist checks `hostname in BLOCKED_HOSTS`, and None is never in that set,
so a file:// URL sails straight through a filter that was only ever written
with network hosts in mind.

This is a different failure mode from every earlier SSRF lab here (05's
total absence of filtering, 40's metadata-endpoint framing, 64's redirect
pivot around a substring blocklist, 65's second unguarded fetch path): here
the one fetch path IS guarded, correctly, for the scheme it was designed
around -- the bug is that "no dangerous host" was implemented as the whole
allow/deny decision, when it needed to also be "no dangerous scheme."

Nullock's automated SSRF prober (`/api/ssrf/test`) requires a URL with a
real network host (it builds a host/port connection to replay against), so
it structurally cannot be pointed at a file:// target -- this lab's bug
sits in the prober's own blind spot, and is found in Repeater instead.

In Nullock:
    1. nullock scope add http://localhost:5070/*
    2. GET /fetch?url=http://127.0.0.1:5070/ -- 400 "blocked host": the
       loopback/metadata blocklist does work for network schemes.
    3. Send /fetch to Repeater and change url to
       file:///app/labs/70-ssrf-file-scheme-bypass/secret.txt (or whatever
       absolute path this lab's secret.txt resolves to on this host --
       printed on the index page). No host in a file:// URL means nothing
       for the blocklist to match, and the response comes back 200 with
       the file's contents.
    4. Confirm success: GET /flag?url=file://<same absolute path> -- same
       fetch function /fetch uses, solved only once the marker inside
       secret.txt actually came back through it.

Fix: allow-list the SCHEME first (http/https only, reject everything else
outright) before ever inspecting the host -- a host check can't save you
from a scheme it was never written to handle.
"""

import hashlib
import os
import urllib.request
from urllib.parse import urlparse

from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-70-ssrf-file-scheme-bypass").hexdigest()[:16]
SECRET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret.txt")
BLOCKED_HOSTS = {"127.0.0.1", "localhost", "169.254.169.254"}


def _blocked(url):
    host = (urlparse(url).hostname or "")
    # VULN: only ever checks the host. A file:// URL has no host, so this
    # is always False for one -- the scheme itself is never inspected.
    return host in BLOCKED_HOSTS or "internal" in host


def _do_fetch(url):
    with urllib.request.urlopen(url, timeout=3) as r:
        return r.read().decode("utf-8", errors="replace")


@app.route("/")
def index():
    return (
        '<a href="/fetch?url=http://example.com/">fetch a URL</a><br>'
        "blocked direct hit: /fetch?url=http://127.0.0.1:5070/<br>"
        "this lab's secret.txt lives at: file://%s" % SECRET_PATH
    )


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="missing url"), 400
    if _blocked(url):
        return jsonify(error="blocked host"), 400
    try:
        return _do_fetch(url), 200, {"Content-Type": "text/plain"}
    except Exception as e:
        return jsonify(error=str(e)), 502


@app.route("/flag")
def flag():
    url = request.args.get("url", "")
    if not url or _blocked(url):
        return jsonify(solved=False), 403
    try:
        body = _do_fetch(url)
    except Exception:
        return jsonify(solved=False), 403
    if urlparse(url).scheme == "file" and "lab70-secret-marker" in body:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False, hint="reading it back isn't enough -- it must come through the file:// scheme"), 403


if __name__ == "__main__":
    with open(SECRET_PATH, "w") as fh:
        fh.write("lab70-secret-marker -- an internal config value, never meant to be network-reachable\n")
    app.run(host="127.0.0.1", port=5070, debug=False)
