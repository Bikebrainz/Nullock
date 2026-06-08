"""
Lab 03 -- Weak JWT signing.

Accepts JWTs in the Authorization header. Verifies with HS256 + a
trivially-guessable secret ("secret"). Also accepts alg=none. The
/admin endpoint reads `role` from the payload without re-checking
trust beyond the signature -- so flipping `role: "admin"` after
re-signing with the leaked secret gives admin access.

Run:
    pip install flask pyjwt
    python app.py

In Nullock:
    1. Hit http://localhost:5003/login -- response includes a JWT.
    2. Open the encoder panel (decoder dropdown -> JWT) and paste
       the token. Notice the JWT decoder annotations:
         [i] HMAC algorithm -- brute-forceable
         [i] role="user" -- try tampering
         [i] expires <X>
    3. Send /admin to Repeater with the token -- get 403.
    4. Decode token, change role to "admin", re-sign with secret
       "secret" (run `python -c 'import jwt; print(jwt.encode({...}, "secret"))'`),
       paste back into Authorization header, fire -- 200.
    5. Alternatively, swap alg to "none" and strip the signature:
       header = base64({"alg":"none","typ":"JWT"})
       payload = base64({"role":"admin","sub":"alice","exp":...})
       token = header + "." + payload + "."
"""

import time
from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

SECRET = "secret"  # VULN: trivial secret

@app.route("/login")
def login():
    payload = { "role": "user", "sub": "alice", "exp": int(time.time()) + 3600 }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    return jsonify(token=token)

@app.route("/admin")
def admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return "missing token", 401
    token = auth.removeprefix("Bearer ")
    try:
        # VULN: accepts alg=none in addition to HS256
        payload = jwt.decode(token, SECRET, algorithms=["HS256", "none"],
                             options={"verify_signature": False if token.endswith(".") else True})
    except Exception as e:
        return f"bad token: {e}", 401
    if payload.get("role") != "admin":
        return "forbidden", 403
    return "welcome, admin"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=False)
