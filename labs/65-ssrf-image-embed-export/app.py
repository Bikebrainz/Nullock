"""
Lab 65 -- SSRF via a report's image-embedding export feature.

Users write a "report" as raw HTML saved to their account, then hit
/export/<id> to render a shareable snapshot. The export step is meant to
work offline (no live remote-image loading once shared), so it walks
every <img src="..."> in the saved HTML server-side, fetches each URL
itself, and inlines the response as a data: URI -- a real pattern (most
"export to PDF" and "email digest" features do exactly this so images
survive after the source page changes). Nobody thought an "image URL"
needed the same host allow-list the app's other outbound-fetch feature
already has, so /export will happily inline whatever internal endpoint
an <img> tag points it at, and the exported HTML hands the response
right back to the report's owner as base64 -- not a blind SSRF, since
the attacker (also the report's author) reads the answer directly.

/fetch?url=... (a normal "attach a remote image" helper elsewhere in the
app) DOES check the same blocklist as lab 64's -- proving the developers
know SSRF is a risk here -- but /export's own internal fetch path never
calls that check at all, because nobody traced the second place the app
makes an outbound request on the user's behalf.

In Nullock:
    1. nullock scope add http://localhost:5065/*
    2. Confirm the guarded path: POST /fetch {"url":
       "http://127.0.0.1:5065/internal"} -- 400 "blocked host".
    3. Save a report whose body embeds the same target as an <img> tag
       instead: POST /report {"html": "<img
       src=\\"http://127.0.0.1:5065/internal\\">"} -> {"id": 1}.
    4. GET /export/1 -- 200, and the returned HTML's <img> src is now a
       data:text/plain;base64,... URI. Decode it (or just read the
       `embedded` field the response also includes for convenience) --
       it's the /internal response, fetched entirely server-side with no
       blocklist in the way.
    5. GET /flag -- solved once /export has actually inlined the
       internal secret for some report.

Fix: route EVERY server-initiated outbound fetch (the "attach an image"
helper and the export renderer alike) through one shared URL-validation
choke point, instead of adding the check to only the endpoint that was
obviously named "fetch".
"""

import hashlib

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-65-ssrf-image-embed-export").hexdigest()[:16]
BLOCKED_SUBSTRINGS = ("127.0.0.1", "169.254.169.254", "/internal")

REPORTS = {}
NEXT_ID = [1]
SSRF_HIT = {"done": False}


@app.route("/")
def index():
    return (
        "Save a report's HTML, then /export/&lt;id&gt; renders it with "
        "every &lt;img&gt; fetched server-side and inlined as a data: URI."
    )


@app.route("/fetch", methods=["POST"])
def fetch():
    # The ONLY outbound path that's actually guarded.
    url = (request.get_json(silent=True) or {}).get("url", "")
    if any(b in url for b in BLOCKED_SUBSTRINGS):
        return jsonify(error="blocked host"), 400
    try:
        r = requests.get(url, timeout=3)
    except requests.RequestException as e:
        return jsonify(error=str(e)), 502
    return jsonify(status=r.status_code, body=r.text[:200])


@app.route("/report", methods=["POST"])
def report():
    html = (request.get_json(silent=True) or {}).get("html", "")
    rid = NEXT_ID[0]
    NEXT_ID[0] += 1
    REPORTS[rid] = html
    return jsonify(id=rid)


@app.route("/internal")
def internal():
    return "INTERNAL SECRET: smtp_password=hunter3"


def _embed_images(html):
    # VULN: fetches every img src itself, with no blocklist at all --
    # the check on /fetch was never wired to this second outbound path.
    import base64
    import re

    embedded = []

    def repl(m):
        src = m.group(1)
        try:
            r = requests.get(src, timeout=3)
            b64 = base64.b64encode(r.content).decode()
            if "INTERNAL SECRET" in r.text:
                SSRF_HIT["done"] = True
            embedded.append(r.text[:200])
            return 'src="data:text/plain;base64,%s"' % b64
        except requests.RequestException:
            return m.group(0)

    return re.sub(r'src="([^"]+)"', repl, html), embedded


@app.route("/export/<int:rid>")
def export(rid):
    html = REPORTS.get(rid)
    if html is None:
        return jsonify(error="no such report"), 404
    rendered, embedded = _embed_images(html)
    return jsonify(html=rendered, embedded=embedded)


@app.route("/flag")
def flag():
    if SSRF_HIT["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5065, debug=False)
