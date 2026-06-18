"""
Lab 40 -- SSRF to internal-only services (cloud-metadata pattern).

/fetch?url=... makes a server-side request to any URL with no allow-list, so
it can reach services the client can't -- this app's own /internal endpoint
(intended to be server-only), or cloud metadata at http://169.254.169.254/.

In Nullock:
    1. nullock scope ... add http://localhost:5040/*
    2. /fetch?url=http://127.0.0.1:5040/internal -- returns the internal secret
       through the server's own request.
    3. On a real cloud host: url=http://169.254.169.254/latest/meta-data/.

Fix: allow-list destination hosts/schemes; block loopback/link-local/RFC1918;
re-resolve and re-check the IP to defeat DNS rebinding.

(Needs `requests`, which is the labs' only non-Flask dependency.)
"""

from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/")
def index():
    return '<a href="/fetch?url=http://example.com/">fetch a URL</a>'


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "url required", 400
    try:
        # VULN: the server fetches an arbitrary, unvalidated URL.
        r = requests.get(url, timeout=3)
        return "fetched %d bytes:\n%s" % (len(r.text), r.text[:500])
    except Exception as e:
        return "error: %s" % e, 502


@app.route("/internal")
def internal():
    # Intended to be an internal-only resource; reachable via SSRF above.
    return "INTERNAL SECRET: db_password=hunter2"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5040, debug=False)
