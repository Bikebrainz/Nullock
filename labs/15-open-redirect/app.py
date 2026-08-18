"""
Lab 15 -- Open redirect.

/go?next=... issues a 302 to whatever `next` says, with no allow-list, so
?next=https://evil.example sends the victim off-site -- the basis for
phishing and OAuth token theft.

In Nullock:
    1. nullock scope add http://localhost:5015/*
    2. Browse http://localhost:5015/go?next=/welcome   (intended)
    3. Send to Repeater, set next to:  https://evil.example/
    4. The response is 302 Location: https://evil.example/ -- off origin.
    5. Run the active probe (openredirect): it confirms only when the
       *resolved* Location host leaves the origin (no same-origin FPs),
       and it tries parser-confusion payloads (//evil, \\evil, @evil).
    6. Confirm success: GET /flag?next=https://evil.example/ -- same
       unvalidated redirect() /go uses, hands back the flag once the
       resolved Location host genuinely leaves this origin.

Fix: allow-list relative paths or exact hosts; reject absolute URLs to
other origins.
"""

import hashlib
from urllib.parse import urlparse
from flask import Flask, request, redirect, jsonify

app = Flask(__name__)

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-15-open-redirect").hexdigest()[:16]


@app.route("/")
def index():
    return '<a href="/go?next=/welcome">continue</a>'


@app.route("/welcome")
def welcome():
    return "welcome back"


@app.route("/go")
def go():
    nxt = request.args.get("next", "/")
    # VULN: redirect to an arbitrary, unvalidated URL.
    return redirect(nxt)


@app.route("/flag")
def flag():
    nxt = request.args.get("next", "/")
    # Same unvalidated redirect() as /go.
    location = redirect(nxt).headers.get("Location", "")
    target = urlparse(location)
    own = urlparse(request.host_url)
    # Solved only when the resolved Location host leaves this origin.
    off_origin = bool(target.netloc) and target.netloc != own.netloc
    if off_origin:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False, location=location), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5015, debug=False)
