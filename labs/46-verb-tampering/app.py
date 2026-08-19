"""
Lab 46 -- HTTP verb tampering (method-based access-control bypass).

/admin is "protected" -- but the check only fires for GET. A POST reaches
the handler and returns the admin content, so the access control is bypassed
simply by changing the request method (a HEAD slips the gate too, returning
200 -- though with the body stripped, per the HTTP spec).

In Nullock:
    1. nullock scope add http://localhost:5046/*
    2. nullock verbtamper http://localhost:5046/admin
       -- GET is denied (403); Nullock retries with alternate verbs and
       method-override headers and flags the ones that flip to 200.
    3. Confirm success: POST /admin -- returns the admin panel with no
       credentials. Then GET /flag -- solved only once a non-GET request
       actually reached the "protected" handler and got the admin content
       back, proving the bypass, not just that GET was denied.

Fix: enforce authorization independent of HTTP method; deny by default for
every verb, not just the one you expected.
"""

from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-46-verb-tampering").hexdigest()[:16]
BYPASSED = {"done": False}


@app.route("/")
def index():
    return '<a href="/admin">admin</a>'


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "GET":
        return "Forbidden", 403          # VULN: only GET is access-controlled
    BYPASSED["done"] = True
    return "ADMIN PANEL -- users: alice, bob, carol"


@app.route("/flag")
def flag_route():
    if BYPASSED["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5046, debug=False)
