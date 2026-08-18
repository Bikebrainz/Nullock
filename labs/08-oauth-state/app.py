"""
Lab 08 -- OAuth `state` parameter misuse leading to CSRF.

The /oauth/start endpoint kicks off an OAuth flow but doesn't include
a `state` parameter; /oauth/callback doesn't verify any state. An
attacker can capture a victim's session into the attacker's
identity-provider account by sending the victim a pre-built callback URL.

Run:
    pip install flask
    python app.py

In Nullock:
    1. Browse /oauth/start -- get redirected to the (mock) IdP.
    2. Note the callback URL has no `state` param.
    3. Repeater: change the `code` to a known attacker code, fire to
       /oauth/callback. The session gets bound to the attacker's code
       without consent.
    4. Confirm success: GET /flag?code=attacker-chosen-code directly,
       with a fresh cookie jar that never visited /oauth/start -- the
       callback still binds the session, proving an attacker can send
       a victim a bare callback link and hijack it without any consent
       step in the way.
    5. Real fix: generate a state value at /oauth/start, store in
       session, verify on callback. If missing or mismatched, abort.
"""

import hashlib
from flask import Flask, request, redirect, session, jsonify

app = Flask(__name__)
app.secret_key = "lab-08-secret"
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-08-oauth-state").hexdigest()[:16]

# Mock IdP. In reality this is google/github/okta.
@app.route("/oauth/start")
def start():
    # VULN: no state param. Should be:
    #   import secrets; state = secrets.token_urlsafe(16)
    #   session["oauth_state"] = state
    #   return redirect(f"...?state={state}&...")
    session["visited_start"] = True  # bookkeeping for /flag only, not a fix
    return redirect("/mock-idp/authorize?client_id=lab&redirect_uri=/oauth/callback")

@app.route("/mock-idp/authorize")
def authorize():
    return redirect("/oauth/callback?code=victim-code-abc")

@app.route("/oauth/callback")
def callback():
    code = request.args.get("code", "")
    if not code:
        return "missing code", 400
    # VULN: doesn't verify state. Attacker who replays this URL with
    # their own code binds the victim's session to the attacker's IdP
    # account.
    session["oauth_code"] = code
    session["logged_in"]  = True
    return jsonify(message="logged in", code=code)

@app.route("/")
def index():
    return jsonify(session=dict(session))

@app.route("/flag")
def flag():
    code = request.args.get("code", "")
    if not code:
        return jsonify(solved=False), 400
    if session.get("visited_start"):
        # Went through the legitimate flow -- doesn't demonstrate the
        # missing-state CSRF gap this lab is about.
        return jsonify(solved=False,
                        reason="hit /flag directly, skipping /oauth/start"), 400
    # VULN: same as /oauth/callback -- no state to verify, so an
    # attacker-forged callback link is honored with no prior consent.
    session["oauth_code"] = code
    session["logged_in"] = True
    return jsonify(solved=True, flag=FLAG)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5008, debug=False)
