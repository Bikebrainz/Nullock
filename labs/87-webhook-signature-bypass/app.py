"""
Lab 87 -- Webhook signature bypass: a payment webhook handler defines the
HMAC signature check right there in the code but never actually calls it,
so any POST claiming to be a completed payment is treated as gospel.

Distinct from Lab 19 (CSRF -- a victim's browser is tricked into sending a
state-changing request carrying real session cookies) and from Lab 84
(GraphQL mass assignment -- the caller IS who they claim to be, they just
set fields they shouldn't): here there is no session and no cookie at all.
The webhook is meant to be server-to-server, authenticated purely by an
HMAC signature over the request body computed with a secret only the real
payment provider holds. The handler reads an `X-Signature` header and even
has a `compute_signature()` helper sitting right next to it, but never
calls that helper to compare against what the header carries -- so anyone
who can reach the URL, no secret required, can mark any order paid.

In Nullock:
    1. GET / -- shows order ORD-1001, status "pending", amount $49.99, and
       the exact JSON body a real payment.completed webhook is documented
       to send.
    2. POST /webhook/payment with that JSON body and header
       X-Signature: deadbeef (garbage -- not a real HMAC of anything) --
       200 {"ok": true}. A correct verifier would reject this outright.
    3. GET /order/ORD-1001 -- status now "paid", despite no signature that
       ever matched the shared secret.
    4. Confirm success: GET /flag -- flips true only once a payment has
       landed behind a signature the server can prove does NOT match
       compute_signature(SECRET, body) for that exact body, showing the
       check is forgeable rather than merely unexercised by this
       walkthrough.
    5. The fix: verify X-Signature with hmac.compare_digest against
       compute_signature(SECRET, raw_body) before trusting any webhook
       event, rejecting with 401 on a mismatch -- the same gap Nullock's
       inspector flags when an endpoint reads an auth-shaped header but
       never branches on its actual value.
"""

import hashlib
import hmac

from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET = "whsec_5c8f3a1e9b2d4671c0a8f6e21d9b5c74"
FLAG = "NULLOCK{webhook_signature_bypass_87}"

ORDERS = {"ORD-1001": {"amount": 49.99, "status": "pending"}}
STATE = {"forged_payment": False}


def compute_signature(secret, raw_body):
    return hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()


@app.route("/")
def index():
    order = ORDERS["ORD-1001"]
    return jsonify(
        order_id="ORD-1001",
        amount=order["amount"],
        status=order["status"],
        webhook_sample={"event": "payment.completed", "order_id": "ORD-1001"},
    )


@app.route("/order/<order_id>")
def order(order_id):
    o = ORDERS.get(order_id)
    if not o:
        return jsonify(error="not found"), 404
    return jsonify(order_id=order_id, **o)


@app.route("/webhook/payment", methods=["POST"])
def webhook_payment():
    raw = request.get_data()
    body = request.get_json(silent=True) or {}
    signature = request.headers.get("X-Signature", "")

    # VULN: compute_signature() exists right above but is never called here.
    # Any non-empty X-Signature (or none at all) is accepted as authentic.
    order_id = body.get("order_id")
    event = body.get("event")
    if event != "payment.completed" or order_id not in ORDERS:
        return jsonify(ok=False, reason="unknown event or order"), 400

    ORDERS[order_id]["status"] = "paid"
    real_signature = compute_signature(SECRET, raw)
    if not hmac.compare_digest(signature, real_signature):
        STATE["forged_payment"] = True
    return jsonify(ok=True)


@app.route("/reset", methods=["POST", "GET"])
def reset():
    ORDERS["ORD-1001"] = {"amount": 49.99, "status": "pending"}
    STATE["forged_payment"] = False
    return jsonify(reset=True)


@app.route("/flag")
def flag():
    if STATE["forged_payment"] and ORDERS["ORD-1001"]["status"] == "paid":
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5087, threaded=True, debug=False)
