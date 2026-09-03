"""
Lab 89 -- Regular expression denial of service (ReDoS) in a username check.

The signup flow validates a candidate username with
`re.match(r'^([a-zA-Z0-9_]+)+$', username)` before ever touching the
"taken names" set. The developer wrote `([a-zA-Z0-9_]+)+` meaning "one or
more allowed characters" -- the outer `+` is a copy-paste leftover with no
purpose the inner `+` doesn't already cover. That redundant nesting is a
textbook catastrophic-backtracking shape: Python's `re` engine is
backtracking-based, so on a string that *almost* matches (a long run of
valid characters followed by one character that breaks the match), it
tries every way of partitioning that run between the inner and outer `+`
before giving up -- 2^n attempts for n valid characters. A 26-character
username plus one trailing `!` takes low seconds on ordinary hardware; a
few characters longer and it's minutes, on a single request, and Flask's
dev server (like many app servers under load) handles one request at a
time per worker -- so that one request stalls every other user's signup
page too. This is CWE-1333 (algorithmic complexity) / OWASP's
uncontrolled-resource-consumption class, not injection or access control:
the string is inert, never reaches a shell/DB/filesystem, and a perfectly
"invalid, rejected" username is what triggers it.

Distinct from Lab 30 (rate-limit bypass -- beating a request-count gate
with a spoofed header, not making any single request expensive) and from
Lab 09 / Lab 85 (race conditions -- a logic window between check and use,
not raw CPU cost): here one client, one request, zero concurrency, is the
entire attack.

In Nullock:
    1. GET / -- shows the signup endpoint and its documented shape.
    2. POST /account/check-username {"username": "alice"} -- 200 in low
       single-digit milliseconds (see the response's own `elapsed_ms`).
       This is also your control: a normal-shaped request is fast.
    3. POST /account/check-username with a username of 26 `a`s followed by
       one `!` (still under typical max-length limits, so no length cap
       saves you) -- 200, same response shape, but `elapsed_ms` jumps into
       the thousands. Repeat with 27 `a`s and it roughly doubles again --
       the exponential signature that separates a genuinely slow backend
       from this. In the desktop app, send it via Repeater and watch the
       History row's own elapsed-time column spike the same way a
       time-based blind-SQLi payload does; the confirmation technique is
       identical.
    4. Confirm without trusting your own stopwatch: GET /flag -- flips
       true only once the server has recorded BOTH a slow, rejected
       (non-matching) request past the threshold AND a fast control
       request, so an unrelated slow server alone can't fake it.
    5. The fix: drop the pointless outer group --
       `re.match(r'^[a-zA-Z0-9_]+$', username)` accepts exactly the same
       strings in linear time (no nested quantifier to backtrack through).
       Where the pattern genuinely needs nesting, compile it with a
       timeout-capable engine (the third-party `regex` module's
       `timeout=` kwarg, or Python 3.11+'s no equivalent stdlib option) or
       validate a length cap *before* the regex ever runs.
"""

import re
import time

from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{redos_username_check_89}"

TAKEN = {"alice", "admin", "root"}

SLOW_MS = 1200.0   # a benign request never gets remotely close to this
FAST_MS = 50.0

STATE = {"slow_seen": False, "control_seen": False}


@app.route("/")
def index():
    return jsonify(
        endpoint="POST /account/check-username",
        body_shape={"username": "string"},
        note="validates the username format before checking availability",
    )


@app.route("/account/check-username", methods=["POST"])
def check_username():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", ""))

    t0 = time.perf_counter()
    # VULN: the outer (...)+  around an already-unbounded inner [...]+  is
    # redundant and catastrophically backtracking on a near-miss input.
    # re.match(r'^[a-zA-Z0-9_]+$', username) is equivalent and linear-time.
    matched = bool(re.match(r"^([a-zA-Z0-9_]+)+$", username))
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    if elapsed_ms >= SLOW_MS and not matched:
        STATE["slow_seen"] = True
    elif elapsed_ms < FAST_MS:
        STATE["control_seen"] = True

    return jsonify(
        username=username,
        valid_format=matched,
        available=matched and username.lower() not in TAKEN,
        elapsed_ms=round(elapsed_ms, 1),
    )


@app.route("/reset", methods=["POST", "GET"])
def reset():
    STATE["slow_seen"] = False
    STATE["control_seen"] = False
    return jsonify(reset=True)


@app.route("/flag")
def flag():
    if STATE["slow_seen"] and STATE["control_seen"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5089, debug=False)
