"""
Lab 20 -- Username enumeration via distinct login errors.

/login returns "Unknown username" for a non-existent account but "Wrong
password" for a real one -- so an attacker can enumerate valid usernames
without ever logging in.

In Nullock:
    1. nullock scope ... add http://localhost:5020/*
    2. Send /login to Intruder; fuzz the `user` field with a wordlist.
    3. Filter responses: a "Wrong password" body means the user exists.

Fix: return ONE generic message ("invalid username or password") for both
cases, and keep response timing constant (hash even for unknown users).
"""

from flask import Flask, request

app = Flask(__name__)
USERS = {"admin": "x", "alice": "y", "bob": "z"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("user", "")
        p = request.form.get("pass", "")
        if u not in USERS:
            return "Unknown username", 401          # VULN: distinct message
        if USERS[u] != p:
            return "Wrong password", 401            # VULN: confirms the user exists
        return "Welcome"
    return ('<form method="post"><input name="user"><input name="pass">'
            '<button>login</button></form>')


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5020, debug=False)
