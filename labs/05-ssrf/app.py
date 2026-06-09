"""
Lab 05 -- SSRF (Server-Side Request Forgery) via URL fetcher.

The /fetch endpoint takes a `url` query param and proxies whatever
it fetches back to the user. No allow-listing on host -- including
RFC 1918, link-local, or AWS metadata IPs. Hands the user the
AWS IMDS contents on a silver platter.

Run:
    pip install flask requests
    python app.py

In Nullock:
    1. Send /fetch?url=https://example.com to Repeater to confirm the
       feature works.
    2. Change url to http://169.254.169.254/latest/meta-data/ -- if
       the lab is running on an EC2 instance, response contains the
       metadata catalog.
    3. Better: start Nullock's OAST sink. Mint a token. Change url to
       the OAST callback URL. Fire. Watch the callback arrive via
       `nullock oast watch`. That demonstrates SSRF without needing
       a real cloud IMDS.
    4. The active probe on this row should raise the "ssrf-cloud-metadata"
       finding automatically.
"""

import requests
from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/")
def index():
    return '<form action="/fetch"><input name="url" /><button>go</button></form>'

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "missing url", 400
    # VULN: no SSRF protection. Anything goes.
    try:
        r = requests.get(url, timeout=5)
        return Response(r.content, status=r.status_code,
                        content_type=r.headers.get("content-type", "text/plain"))
    except Exception as e:
        return f"fetch error: {e}", 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5005, debug=False)
