"""
Lab 09 -- Race condition in a balance-transfer endpoint.

POST /transfer reads the user's current balance, checks if it's enough,
then deducts. Time-of-check vs time-of-use bug: if you fire two
concurrent requests, both pass the balance check before either has
deducted. Net effect: you can spend more than you have.

Run:
    pip install flask
    python app.py

In Nullock:
    1. POST /transfer?amount=80 -- single shot, succeeds, balance now 20.
       (Initial balance = 100.)
    2. Reset via POST /reset.
    3. Use Intruder. Load /transfer?amount=80 as the template.
       Payload set: any 5 entries (the values don't matter).
       Set "concurrent threads" to 5.
    4. Fire. All 5 deduct succeed -- balance now -300 instead of -300.
       Real apps lose real money this way (BTC exchanges, gift card
       redemption, etc).
    5. Confirm success: GET /flag -- returns the flag once the balance
       has actually gone negative, which single-shot requests can
       never do (the check always blocks them); only the race wins it.
    6. Real fix: SELECT ... FOR UPDATE in a single transaction, or
       atomic decrement + check, or a queue.
"""

import hashlib, threading
from flask import Flask, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-09-race-condition").hexdigest()[:16]

class State:
    balance = 100
    lock_unused = threading.Lock()   # intentionally not used in /transfer

S = State()

@app.route("/balance")
def balance():
    return jsonify(balance=S.balance)

@app.route("/transfer")
def transfer():
    # query param ?amount=N
    from flask import request
    amount = int(request.args.get("amount", "10"))
    # VULN: read-then-write without atomicity.
    if S.balance < amount:
        return jsonify(ok=False, reason="insufficient"), 400
    # Simulate any real-world post-check work (db roundtrip).
    import time; time.sleep(0.05)
    S.balance -= amount
    return jsonify(ok=True, new_balance=S.balance)

@app.route("/reset", methods=["POST", "GET"])
def reset():
    S.balance = 100
    return jsonify(balance=S.balance)

@app.route("/flag")
def flag():
    if S.balance < 0:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False, balance=S.balance), 403

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5009, threaded=True, debug=False)
