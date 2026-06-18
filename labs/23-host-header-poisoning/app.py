"""
Lab 23 -- Host header injection -> password-reset poisoning.

POST /forgot builds the password-reset link from the incoming Host header.
Spoof Host: and the reset link points at the attacker's server -- when the
victim clicks it, their reset token lands in the attacker's logs.

In Nullock:
    1. nullock scope ... add http://localhost:5023/*
    2. Send /forgot to Repeater with body user=alice and header
           Host: evil.example
    3. The returned 'reset link' uses evil.example -- poisoned.

Fix: never build absolute URLs from the Host header; use a configured
canonical base URL and validate Host against an allow-list.
"""

from flask import Flask, request
import secrets

app = Flask(__name__)


@app.route("/")
def index():
    return ('<form method="post" action="/forgot">'
            '<input name="user" value="alice"><button>reset</button></form>')


@app.route("/forgot", methods=["POST"])
def forgot():
    user = request.form.get("user", "")
    token = secrets.token_urlsafe(16)
    # VULN: reset link built from the attacker-controlled Host header.
    link = "https://" + request.host + "/reset?token=" + token + "&user=" + user
    return "Password reset link sent (simulated): " + link


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5023, debug=False)
