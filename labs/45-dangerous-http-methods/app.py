"""
Lab 45 -- Dangerous HTTP methods enabled.

The server advertises write methods (PUT/DELETE/PATCH) in its OPTIONS
Allow header -- surface for unauthenticated file upload/deletion if those
handlers aren't separately access-controlled.

In Nullock:
    1. nullock scope ... add http://localhost:5045/*
    2. nullock methods http://localhost:5045/
       -- reads OPTIONS Allow and flags dangerous-http-methods.

Fix: disable methods you don't serve at the server/router; allow only the
verbs each route actually needs.
"""

from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/", methods=["GET", "OPTIONS"])
def index():
    if request.method == "OPTIONS":
        resp = make_response("", 204)
        # VULN: advertises write methods the app shouldn't expose.
        resp.headers["Allow"] = "OPTIONS, GET, HEAD, PUT, DELETE, PATCH"
        return resp
    return "<h1>file store</h1><p>send OPTIONS to enumerate methods</p>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5045, debug=False)
