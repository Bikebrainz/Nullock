"""
Lab 36 -- HTTP parameter pollution (inconsistent duplicate handling).

/transfer authorizes against the FIRST occurrence of a duplicated parameter
but debits the LAST -- so amount=10&amount=10000 passes a "<=100" check on
10 while 10000 is what actually moves.

In Nullock:
    1. nullock scope ... add http://localhost:5036/*
    2. POST /transfer amount=10  -> authorized + debited 10.
    3. Send to Repeater, body:  amount=10&amount=10000
    4. The check sees 10 (allowed); the debit uses 10000 -- HPP bypass.

Fix: reject duplicate parameters (or canonicalize to one value) and use a
single parsed value consistently for both the check and the action.
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def index():
    return ('<form method="post" action="/transfer">'
            '<input name="amount" value="10"><button>transfer</button></form>')


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    vals = request.form.getlist("amount") or request.args.getlist("amount")
    if not vals:
        return "amount required", 400
    # VULN: the check uses the FIRST value, the debit uses the LAST.
    check_amount = int(vals[0])
    debit_amount = int(vals[-1])
    if check_amount > 100:
        return "amount over limit", 403
    return "authorized (checked %d) -- debited %d" % (check_amount, debit_amount)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5036, debug=False)
