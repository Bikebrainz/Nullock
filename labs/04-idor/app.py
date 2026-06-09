"""
Lab 04 -- IDOR (Insecure Direct Object Reference).

The /profile/<id> endpoint returns the profile for any user ID without
checking that the requester is allowed to view it. Auth is via a
trivial header `X-User: <id>` to keep the lab clear.

Run:
    pip install flask
    python app.py

In Nullock:
    1. Browse http://localhost:5004/login as alice (id=1). Note the
       X-User cookie set in the response.
    2. Browse /profile/1 -- get alice's profile.
    3. Send to Repeater. Change URL to /profile/2.
    4. Fire -- you see bob's profile despite being logged in as alice.
    5. Walk every ID with Intruder: payload set = [1..100], scan
       responses for emails / phone numbers / SSNs.
"""

from flask import Flask, request, make_response, jsonify

app = Flask(__name__)

USERS = {
    1: {"name": "alice", "email": "alice@example.com", "ssn": "111-11-1111"},
    2: {"name": "bob",   "email": "bob@example.com",   "ssn": "222-22-2222"},
    3: {"name": "carol", "email": "carol@example.com", "ssn": "333-33-3333"},
}

@app.route("/login")
def login():
    r = make_response("hi alice")
    r.set_cookie("X-User", "1")
    return r

@app.route("/profile/<int:uid>")
def profile(uid):
    # VULN: doesn't check request.cookies["X-User"] == uid
    if uid not in USERS:
        return "no such user", 404
    return jsonify(USERS[uid])

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5004, debug=False)
