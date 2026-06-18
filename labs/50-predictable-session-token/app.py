"""
Lab 50 -- Predictable session tokens.

Session IDs are a simple incrementing counter, so once you observe one you
can predict (and hijack) every other user's session. Nullock's sequencer
scores the randomness of a captured corpus of tokens.

In Nullock:
    1. nullock scope add http://localhost:5050/*
    2. Collect a handful of session cookies (log in repeatedly, or replay in
       Repeater), then: nullock sequencer analyze <tok1> <tok2> ...
       -- the verdict comes back "predictable" (sequential, low entropy).

Fix: generate session IDs from a CSPRNG (secrets.token_urlsafe(32)); never
derive them from a counter, timestamp, or user data.
"""

from flask import Flask, make_response

app = Flask(__name__)

_counter = 1000


@app.route("/login", methods=["GET", "POST"])
def login():
    global _counter
    _counter += 1
    resp = make_response("logged in")
    # VULN: sequential, guessable session identifier.
    resp.set_cookie("session", str(_counter))
    return resp


@app.route("/")
def index():
    return '<a href="/login">log in</a>'


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
