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

Fix: allow-list relative paths or exact hosts; reject absolute URLs to
other origins.
"""

from flask import Flask, request, redirect

app = Flask(__name__)


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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5015, debug=False)
