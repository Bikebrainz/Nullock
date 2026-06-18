"""
Lab 28 -- Business-logic flaw: client-controlled price / negative quantity.

POST /checkout trusts the `price` and `qty` fields from the request, so a
buyer can set their own price (price=0.01) or a negative quantity to invert
the charge. The server never re-derives the total from a trusted catalog.

In Nullock:
    1. nullock scope ... add http://localhost:5028/*
    2. POST /checkout item=widget&price=99.00&qty=1   (legit)
    3. Send to Repeater; set price=0.01 (or qty=-5) -- the total obeys you.

Fix: look up the price server-side from a trusted catalog by item id;
validate qty > 0; never trust client-supplied prices or totals.
"""

from flask import Flask, request

app = Flask(__name__)


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
    return "Charged $%.2f for %d x %s" % (total, qty, item)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5028, debug=False)
