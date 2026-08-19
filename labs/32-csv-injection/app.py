"""
Lab 32 -- CSV / formula injection.

/feedback stores a message; /export streams all messages as CSV with no
neutralization. A message beginning with = + - or @ becomes an executable
formula when the CSV is opened in Excel/Sheets (data exfil or command
execution via DDE).

In Nullock:
    1. nullock scope add http://localhost:5032/*
    2. POST /feedback  msg==HYPERLINK("http://evil","click")
    3. GET /export -- the cell starts with '=' (live formula on open).
    4. Confirm success: GET /flag -- solved only once /export was actually
       called while an unneutralized formula-leading message was stored,
       proving the raw formula reached the exported CSV cell.

Fix: prefix risky leading chars (= + - @ tab CR) with a single quote, or
quote the field, when exporting user-controlled data to CSV.
"""

from flask import Flask, request, Response, redirect, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-32-csv-injection").hexdigest()[:16]
MSGS = []
EXPORTED = {"triggered": False}


@app.route("/")
def index():
    return ('<a href="/feedback">leave feedback</a> | '
            '<a href="/export">export CSV</a>')


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        MSGS.append(request.form.get("msg", ""))
        return redirect("/feedback")
    return '<form method="post"><input name="msg"><button>send</button></form>'


@app.route("/export")
def export():
    # VULN: user values written raw into CSV cells (no formula neutralization).
    if any(m[:1] in ("=", "+", "-", "@") for m in MSGS):
        EXPORTED["triggered"] = True
    rows = "row,message\n" + "".join("%d,%s\n" % (i, m) for i, m in enumerate(MSGS))
    return Response(rows, mimetype="text/csv")


@app.route("/flag")
def flag_route():
    if EXPORTED["triggered"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5032, debug=False)
