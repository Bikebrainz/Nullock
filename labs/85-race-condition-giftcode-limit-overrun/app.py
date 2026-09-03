"""
Lab 85 -- Race condition (limit overrun): a single-use gift code's
"already redeemed" check races its own write, so N concurrent redemptions
all read used=False before any of them writes used=True -- one code,
multiple payouts.

Distinct from Lab 09 (balance-transfer TOCTOU: a numeric balance overdrawn
below zero by racing a spend against itself) in exploit shape, not just
theme: this is the "limit overrun" pattern -- a boolean one-time token
(GIFT_CODES[code]["used"]) is checked, then, after a deliberate fulfilment
delay, set, with the same missing atomicity across the gap. Lab 09 wins by
watching a balance go negative, something no sequence of single-shot
requests can ever do; this one wins by watching ONE code's credit land in
the wallet more than once, which a single, non-concurrent replay of the
same request can never do either -- POST it twice in a row and the second
call always sees used=True and 403s. Only requests that land inside the
race window, concurrently, both read the pre-write state.

In Nullock:
    1. GET /wallet -- balance 0.
    2. POST /api/redeem?code=WELCOME50 -- single shot, credits +50, wallet
       balance now 50. POST it again -- 403 "already redeemed", balance
       unchanged. The check works correctly under normal sequential use.
    3. POST /reset -- zeroes the wallet and un-redeems the code.
    4. Use Nullock's race probe (Tests tab -> type "race", or Intruder
       with N concurrent identical requests) against
       POST /api/redeem?code=WELCOME50 with count >= 5.
    5. Several of the concurrent requests all read used=False before any
       of them writes used=True, so several all credit +50. Wallet balance
       ends up a multiple of 50 greater than one redemption should allow.
    6. Confirm success: GET /flag -- flips true only once the wallet
       balance exceeds a single redemption's value (50), a state no
       sequential use of this endpoint can ever reach.
    7. Fix: hold a per-code lock (or an atomic
       UPDATE ... SET used=1 WHERE used=0, checking rows-affected) across
       the check-and-set, not just around the write.
"""

import hashlib
import time
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-85-race-limit-overrun").hexdigest()[:16]

GIFT_CODES = {"WELCOME50": {"value": 50, "used": False}}
WALLET = {"balance": 0}


@app.route("/wallet")
def wallet():
    return jsonify(balance=WALLET["balance"])


@app.route("/api/redeem", methods=["POST"])
def redeem():
    code = request.args.get("code", "")
    gift = GIFT_CODES.get(code)
    if gift is None:
        return jsonify(ok=False, reason="unknown code"), 404
    # VULN: check-then-act with no lock across the gap. Under normal,
    # sequential use the second call always sees used=True and 403s --
    # only requests that land concurrently can both slip past the check
    # before either write lands.
    if gift["used"]:
        return jsonify(ok=False, reason="already redeemed"), 403
    time.sleep(0.05)  # simulates a real fulfilment round-trip (ledger write, email, ...)
    gift["used"] = True
    WALLET["balance"] += gift["value"]
    return jsonify(ok=True, credited=gift["value"], balance=WALLET["balance"])


@app.route("/reset", methods=["POST", "GET"])
def reset():
    for gift in GIFT_CODES.values():
        gift["used"] = False
    WALLET["balance"] = 0
    return jsonify(balance=WALLET["balance"])


@app.route("/flag")
def flag():
    single_value = GIFT_CODES["WELCOME50"]["value"]
    if WALLET["balance"] > single_value:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False, balance=WALLET["balance"]), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5085, threaded=True, debug=False)
