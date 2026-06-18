"""
Lab 46 -- HTTP verb tampering (method-based access-control bypass).

/admin is "protected" -- but the check only fires for GET. A POST reaches
the handler and returns the admin content, so the access control is bypassed
simply by changing the request method (a HEAD slips the gate too, returning
200 -- though with the body stripped, per the HTTP spec).

In Nullock:
    1. nullock scope ... add http://localhost:5046/*
    2. nullock verbtamper http://localhost:5046/admin
       -- GET is denied (403); Nullock retries with alternate verbs and
       method-override headers and flags the ones that flip to 200.

Fix: enforce authorization independent of HTTP method; deny by default for
every verb, not just the one you expected.
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def index():
    return '<a href="/admin">admin</a>'


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "GET":
        return "Forbidden", 403          # VULN: only GET is access-controlled
    return "ADMIN PANEL -- users: alice, bob, carol"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5046, debug=False)
