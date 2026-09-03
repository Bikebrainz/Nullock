"""
Lab 86 -- JS recon: an exposed production source map hands back the
pre-minification source, and that source hardcodes an internal API token
the minified bundle itself never shows in readable form.

Distinct from Lab 25 (a plaintext AWS key sitting directly in app.js, no
recon needed) and Lab 48 (raw files like .env/.git served from the web
root): here the SECRET is not in anything a page links to or a directory
listing would surface. It only exists inside app.min.js.map's
`sourcesContent`, reachable solely by following the minified bundle's own
`//# sourceMappingURL` comment -- exactly the two-hop chain Nullock's JS
recon probe automates (fetch the page -> pull <script src> bundles ->
follow each bundle's sourceMappingURL -> mine secrets out of what comes
back), and exactly what a plain "view source" on the page never reveals.

In Nullock:
    1. GET / -- a plain dashboard-links page, references /static/app.min.js.
       View its response body: no secret anywhere.
    2. GET /static/app.min.js -- single-line minified JS. No readable
       secret in it either, but its last line names a source map:
       `//# sourceMappingURL=app.min.js.map`.
    3. Run Nullock's JS recon probe against / (Scans tab -> JS recon, or
       `nullock jsrecon <url>`). It fetches the bundle, follows the
       sourceMappingURL, confirms /static/app.min.js.map is reachable
       (flags a source-map-exposed finding), and mines the map's
       sourcesContent for hardcoded secrets -- surfacing a generic-secret
       hit for INTERNAL_API_TOKEN.
    4. Confirm by hand: GET /static/app.min.js.map, read the
       sourcesContent[0] string -- the un-minified original source,
       including `const INTERNAL_API_TOKEN = "nlk_live_..."` and a comment
       naming the endpoint it unlocks.
    5. GET /internal/export-users with header
       `X-Internal-Token: <the leaked value>` -- 200, dumps the (fake)
       user table. Without the header, or with the wrong value, 403.
    6. Confirm success: GET /flag -- flips true only once the correct
       token has actually been used against /internal/export-users, not
       merely extracted.
    7. Fix: never ship .map files (or gate them behind the same auth as
       the app) in production, and never hardcode a live credential into
       source at all -- minification is not a security boundary, and a
       source map undoes it for anyone who looks.
"""

from flask import Flask, request, jsonify, Response

app = Flask(__name__)

INTERNAL_TOKEN = "nlk_live_8f2ac9d14e7b4c108f6a3d92c1e0b7aa"
FLAG = "NULLOCK{js_sourcemap_secret_leak_86}"
STATE = {"used_token": False}

INDEX_HTML = """<!doctype html>
<html><head><title>Acme Internal Dashboard</title>
<script src="/static/app.min.js"></script></head>
<body><h1>Acme Internal Dashboard</h1>
<p>Sign in with SSO to continue.</p></body></html>
"""

# What a real bundler would emit: unreadable, no secret in sight, but a
# trailing sourceMappingURL comment pointing at the map that undoes all of it.
APP_MIN_JS = (
    "(function(){var a=document.title;console.log(a)})();\n"
    "//# sourceMappingURL=app.min.js.map\n"
)

# The pre-minification source, exactly as it would have been authored --
# hardcoded token and all. This is what ships inside sourcesContent.
ORIGINAL_SOURCE = """// dashboard bootstrap
var pageTitle = document.title;
console.log(pageTitle);

// TODO(before launch): move this to the secrets manager, not source control.
const INTERNAL_API_TOKEN = "%s";

function exportUsers() {
  // internal-only, used by the ops team's export button
  return fetch("/internal/export-users", {
    headers: { "X-Internal-Token": INTERNAL_API_TOKEN },
  });
}
""" % INTERNAL_TOKEN

APP_MIN_JS_MAP = {
    "version": 3,
    "file": "app.min.js",
    "sources": ["app.js"],
    "names": [],
    "mappings": "AAAA",
    "sourcesContent": [ORIGINAL_SOURCE],
}


@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


@app.route("/static/app.min.js")
def bundle():
    return Response(APP_MIN_JS, mimetype="application/javascript")


@app.route("/static/app.min.js.map")
def sourcemap():
    # VULN: a production build artifact that hands back the original,
    # commented, secret-bearing source -- no auth, no host restriction.
    return jsonify(APP_MIN_JS_MAP)


@app.route("/internal/export-users")
def export_users():
    token = request.headers.get("X-Internal-Token", "")
    if token != INTERNAL_TOKEN:
        return jsonify(ok=False, reason="missing or invalid X-Internal-Token"), 403
    STATE["used_token"] = True
    return jsonify(ok=True, users=[
        {"id": 1, "email": "alice@acme.test"},
        {"id": 2, "email": "bob@acme.test"},
    ])


@app.route("/reset", methods=["POST", "GET"])
def reset():
    STATE["used_token"] = False
    return jsonify(reset=True)


@app.route("/flag")
def flag():
    if STATE["used_token"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5086, threaded=True, debug=False)
