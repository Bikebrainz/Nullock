"""
Lab 57 -- Subdomain takeover via a dangling GitHub Pages CNAME.

status.techcorp.example used to be a GitHub Pages status dashboard. The team
retired it and deleted the GitHub Pages project, but nobody removed the DNS
CNAME record pointing status.techcorp.example -> techcorp.github.io. GitHub
Pages now serves its "no site here" error for that hostname -- and anyone
can register a repo named techcorp.github.io on GitHub, publish a Pages site
under it, and instantly serve their own content on the company's own
subdomain: CWE-284, the same class Nullock's active `takeover` probe
fingerprints (a dangling-service body match against a curated table of
branded error pages).

This lab app IS that dangling endpoint (in reality a separate subdomain and
host; collapsed to one process here) -- every path returns the exact page
GitHub Pages serves for an unclaimed custom domain.

Run:
    pip install flask
    python app.py

In Nullock:
    1. nullock scope add http://localhost:5057/*
    2. POST /api/takeover/test {"url": "http://127.0.0.1:5057/"} -- fetches
       the host and matches its body against Nullock's curated dangling-
       service fingerprint table (subjack/nuclei-style detection).
    3. The response comes back with a GitHub Pages hit ("There isn't a
       GitHub Pages site here.") at "high" confidence, graded on the 404
       status the fingerprint policy requires for a real candidate (a
       branded phrase quoted on a live 2xx page is demoted instead).
    4. Confirm success: GET /flag -- solved only once this lab's own root
       route has actually served that fingerprint body to a request
       carrying Nullock's real takeover-probe User-Agent
       (`Nullock/takeover`, set by the probe's own request builder), i.e.
       genuine tool-driven detection, not just opening the page in a
       browser.

Fix: whenever a service backing a CNAME/DNS record is decommissioned,
remove the DNS record in the SAME change; track third-party DNS records
in an inventory and alert when their target stops resolving or starts
serving an unclaimed-resource page; periodically re-scan owned domains for
dangling-service fingerprints.
"""

import hashlib

from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-57-subdomain-takeover").hexdigest()[:16]

GITHUB_PAGES_404 = """<!DOCTYPE html>
<html>
<head><title>Site not found &middot; GitHub Pages</title></head>
<body>
<h1>404</h1>
<p>There isn't a GitHub Pages site here.</p>
<p>If you're trying to publish one, read the full documentation to learn how
to set up GitHub Pages for your repository, organization, or user
account.</p>
</body>
</html>"""

_detected = {"done": False}


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def dangling(path):
    # VULN: the CNAME is dangling -- every path on this "subdomain" now
    # serves GitHub Pages' own unclaimed-custom-domain error, at a genuine
    # 404 (not a live 2xx page merely quoting the phrase), which is exactly
    # what makes it a confirmable takeover candidate rather than noise.
    if request.headers.get("User-Agent") == "Nullock/takeover":
        _detected["done"] = True
    return GITHUB_PAGES_404, 404


@app.route("/flag")
def flag_route():
    if _detected["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5057, debug=False)
