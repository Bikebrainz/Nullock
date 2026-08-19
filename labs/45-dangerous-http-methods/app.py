"""
Lab 45 -- Dangerous HTTP methods enabled.

The server advertises write methods (PUT/DELETE/PATCH) in its OPTIONS
Allow header -- and, worse, actually implements them with no
authentication: an unauthenticated PUT overwrites the file store's content.

In Nullock:
    1. nullock scope add http://localhost:5045/*
    2. nullock methods http://localhost:5045/
       -- reads OPTIONS Allow and flags dangerous-http-methods.
    3. PUT a body to / -- it overwrites the file store's content with no
       auth check.
    4. Confirm success: GET /flag -- solved only once an unauthenticated PUT
       actually changed the stored content, proving the advertised method
       is not just listed but genuinely exploitable.

Fix: disable methods you don't serve at the server/router; allow only the
verbs each route actually needs; require authentication + authorization on
every state-changing method.
"""

from flask import Flask, request, make_response, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-45-dangerous-http-methods").hexdigest()[:16]
STORE = {"content": "<h1>file store</h1><p>send OPTIONS to enumerate methods</p>"}
WRITE_DONE = {"done": False}


@app.route("/", methods=["GET", "OPTIONS", "PUT", "DELETE", "PATCH"])
def index():
    if request.method == "OPTIONS":
        resp = make_response("", 204)
        # VULN: advertises write methods the app shouldn't expose.
        resp.headers["Allow"] = "OPTIONS, GET, HEAD, PUT, DELETE, PATCH"
        return resp
    if request.method in ("PUT", "PATCH"):
        # VULN: unauthenticated write -- no auth/authorization check at all.
        body = request.get_data(as_text=True)
        if body and body != STORE["content"]:
            STORE["content"] = body
            WRITE_DONE["done"] = True
        return "stored", 200
    if request.method == "DELETE":
        # VULN: unauthenticated delete.
        STORE["content"] = ""
        WRITE_DONE["done"] = True
        return "deleted", 200
    return STORE["content"]


@app.route("/flag")
def flag_route():
    if WRITE_DONE["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5045, debug=False)
