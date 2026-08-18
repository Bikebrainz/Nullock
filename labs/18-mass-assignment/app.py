"""
Lab 18 -- Mass assignment / over-posting.

PATCH /api/profile updates the profile object by blindly merging every key
in the request body -- including privileged fields the UI never exposes,
like "role" or "is_admin". An attacker adds those keys to escalate.

In Nullock:
    1. nullock scope add http://localhost:5018/*
    2. PATCH /api/profile  body {"name":"alice"}   -> is_admin stays false
    3. Send to Repeater, body:  {"name":"alice","is_admin":true,"role":"admin"}
    4. The response shows is_admin: true -- privilege escalated.
    5. Run the active probe (mass-assignment): it tries a battery of
       privileged field names and flags any that stick.
    6. Confirm success: GET /flag -- returns the flag once is_admin AND
       role have actually flipped to admin, which no allow-listed field
       could ever do.

Fix: bind only an explicit allow-list of fields; never merge the raw
request body into your model/object.
"""

import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-18-mass-assignment").hexdigest()[:16]
profile = {"name": "alice", "email": "alice@corp.example",
           "role": "user", "is_admin": False}


@app.route("/")
def index():
    return "PATCH /api/profile with a JSON body to update your profile."


@app.route("/api/profile", methods=["GET", "PATCH", "POST"])
def update():
    if request.method in ("PATCH", "POST"):
        data = request.get_json(silent=True) or request.form.to_dict()
        # VULN: merge every supplied key -- no field allow-list.
        for k, v in data.items():
            profile[k] = v
    return jsonify(profile)


@app.route("/flag")
def flag():
    # Solved only when BOTH privileged fields have flipped -- name/email
    # alone (the allow-listed, legitimate fields) can never do this.
    if profile.get("is_admin") is True and profile.get("role") == "admin":
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False, profile=profile), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5018, debug=False)
