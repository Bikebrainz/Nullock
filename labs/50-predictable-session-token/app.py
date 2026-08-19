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
    3. Confirm success: log in once (note the issued session id N), then
       GET /whoami with Cookie: session=<N+1> -- a session you never logged
       in for, but the server accepts it anyway because it's the next
       predictable value. Then GET /flag -- solved only once an unissued,
       merely-predicted session was actually accepted, proving hijack via
       prediction rather than just observing one token's low entropy.

Fix: generate session IDs from a CSPRNG (secrets.token_urlsafe(32)); never
derive them from a counter, timestamp, or user data.
"""

from flask import Flask, make_response, request, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-50-predictable-session-token").hexdigest()[:16]

_counter = 1000
ISSUED = set()
HIJACKED = {"done": False}


@app.route("/login", methods=["GET", "POST"])
def login():
    global _counter
    _counter += 1
    ISSUED.add(_counter)
    resp = make_response("logged in")
    # VULN: sequential, guessable session identifier.
    resp.set_cookie("session", str(_counter))
    return resp


@app.route("/whoami")
def whoami():
    tok = request.cookies.get("session", "")
    if tok.isdigit():
        n = int(tok)
        # VULN: any sequential id up to a few ahead of the last issued one is
        # accepted, whether or not it was ever actually issued via /login.
        if 1000 < n <= _counter + 5:
            if n not in ISSUED:
                HIJACKED["done"] = True
            return "welcome back, session %d" % n
    return "no valid session", 401


@app.route("/")
def index():
    return '<a href="/login">log in</a>'


@app.route("/flag")
def flag_route():
    if HIJACKED["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
