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

Fix: bind only an explicit allow-list of fields; never merge the raw
request body into your model/object.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5018, debug=False)
