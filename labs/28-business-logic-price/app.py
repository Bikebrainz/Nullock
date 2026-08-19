"""
Lab 28 -- Business-logic flaw: client-controlled price / negative quantity.

POST /checkout trusts the `price` and `qty` fields from the request, so a
buyer can set their own price (price=0.01) or a negative quantity to invert
the charge. The server never re-derives the total from a trusted catalog.

In Nullock:
    1. nullock scope add http://localhost:5028/*
    2. POST /checkout item=widget&price=99.00&qty=1   (legit)
    3. Send to Repeater; set price=0.01 (or qty=-5) -- the total obeys you.
    4. Confirm success: GET /flag -- solved only once a checkout actually
       cleared for a total far below the real catalog price (99.00), proof
       the tampered price/qty was accepted, not just submitted.

Fix: look up the price server-side from a trusted catalog by item id;
validate qty > 0; never trust client-supplied prices or totals.
"""

from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-28-business-logic-price").hexdigest()[:16]
CATALOG_PRICE = {"widget": 99.00}
LAST = {}   # records the most recent checkout's item/total


@app.route("/")
def index():
    return ('<form method="post" action="/checkout">'
            '<input name="item" value="widget">'
            '<input name="price" value="99.00">'
            '<input name="qty" value="1"><button>buy</button></form>')


@app.route("/checkout", methods=["POST"])
def checkout():
    item = request.form.get("item", "")
    # VULN: price + qty taken from the client, not a trusted catalog.
    price = float(request.form.get("price", "0") or 0)
    qty = int(request.form.get("qty", "1") or 1)
    total = price * qty
    LAST["item"] = item
    LAST["total"] = total
    return "Charged $%.2f for %d x %s" % (total, qty, item)


@app.route("/flag")
def flag_route():
    # Solved only if the last checkout's item is real (in the trusted
    # catalog) but its charged total is far below what that catalog price
    # implies -- proving the client-supplied price/qty was trusted verbatim.
    true_price = CATALOG_PRICE.get(LAST.get("item"))
    if true_price and LAST.get("total", true_price) < 1.0:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5028, debug=False)
