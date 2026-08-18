"""
Lab 01 -- Reflected XSS via search echo.

The /search endpoint echoes the `q` query parameter back into the HTML
response without escaping it. Classic reflected XSS.

Run:
    pip install flask
    python app.py

In Nullock:
    1. nullock scope add http://localhost:5001/*
    2. Browse http://localhost:5001/search?q=hello
    3. Right-click the captured row -> Send to Repeater
    4. Change q to: <img src=x onerror=alert(1)>
    5. Fire. Inspect response body -- canary survives unescaped.
    6. Run the active probe on the row (probe button) and watch the
       passive scanner raise a "reflected-xss" finding.
    7. Confirm success: GET /flag?q=<img src=x onerror=alert(1)> --
       the endpoint replays the same unsafe interpolation /search uses
       and hands back the flag once your payload survives unescaped.

The fix would be to render via jinja's autoescape or escape() the
value before interpolation.
"""

import hashlib, re
from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-01-xss-mirror").hexdigest()[:16]

@app.route("/")
def index():
    return """<!doctype html>
<title>nullock lab 01</title>
<form action="/search"><input name="q" placeholder="search me" /><button>go</button></form>
"""

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: q interpolated raw. Try ?q=<script>alert(1)</script>
    return f"""<!doctype html>
<title>lab 01 -- results</title>
<p>You searched for: {q}</p>
<p><a href="/">back</a></p>
"""

@app.route("/flag")
def flag():
    q = request.args.get("q", "")
    reflected = f"<p>You searched for: {q}</p>"
    # Solved when the raw payload both looks like script/event-handler
    # markup AND survives unescaped in the same interpolation /search
    # uses -- proves the reflection is exploitable, not just present.
    looks_like_xss = re.search(r"<script[\s>]|on\w+\s*=", q, re.I)
    if looks_like_xss and q in reflected:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
