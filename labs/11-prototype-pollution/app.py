"""
Lab 11 -- Prototype pollution via deep-merge.

The /config endpoint deep-merges JSON request bodies into an in-memory
config object using a naive recursive walker. Sending {"__proto__":
{"isAdmin": true}} pollutes the global Object prototype if this were
JS; the Python equivalent is a class-attribute injection via
__class__/__dict__. We model the impact: the `is_admin` flag flips
across all sessions.

Run:
    pip install flask
    python app.py

In Nullock:
    1. GET /me -- response { name: "alice", is_admin: false }.
    2. POST /config with body {"theme":"dark"} -- normal merge.
    3. POST /config with body {"__class__":{"is_admin":true}} -- a
       naive walker writes to the User class's attributes.
    4. GET /me again -- is_admin now true for every user.
    5. Real fix: validate keys against an allow-list before merge;
       refuse __proto__ / __class__ / constructor in keys.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

class User:
    name = "alice"
    is_admin = False

def deep_merge(target, src):
    for k, v in src.items():
        # VULN: no key allow-list. Writing to obj.__class__.is_admin
        # poisons the whole class.
        if isinstance(v, dict) and hasattr(target, k):
            attr = getattr(target, k)
            if isinstance(attr, type):           # class object
                for k2, v2 in v.items():
                    setattr(attr, k2, v2)
            else:
                deep_merge(attr, v)
        else:
            setattr(target, k, v)

USER = User()

@app.route("/me")
def me():
    return jsonify(name=USER.name, is_admin=USER.is_admin)

@app.route("/config", methods=["POST"])
def config():
    src = request.get_json(silent=True) or {}
    deep_merge(USER, src)
    return jsonify(ok=True)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5011, debug=False)
