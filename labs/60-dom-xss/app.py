"""
Lab 60 -- DOM-based XSS via a location-derived innerHTML sink.

The landing page reads the URL fragment (everything after `#`) entirely in
client-side JavaScript and writes it straight into the DOM with
`.innerHTML` -- no escaping, and the value never touches the server at all
(a fragment is never sent in the HTTP request). The HTTP response is
byte-identical no matter what the fragment holds, so a passive check that
only greps the response body for a reflected payload finds nothing; the
sink only fires once a real browser parses and runs the inline script.

In Nullock:
    1. nullock scope add http://localhost:5060/*
    2. Fetch / through the Proxy -- the passive scanner's DOM-XSS sink
       check flags it anyway: it reads the inline script source itself and
       matches the `.innerHTML = ...location...` pattern, no execution
       needed. That confirms the sink exists; it does not yet prove it is
       exploitable, since not every match is (the pattern also fires on
       code that already sanitizes first).
    3. Read the flagged script: it takes `location.hash`, strips a
       `#name=` prefix, and assigns the decoded remainder to
       `innerHTML` -- no escaping. That's a real sink.
    4. Craft
       http://localhost:5060/#name=<img src=x onerror="fetch('/pwn')">
       and open it in an actual browser (the fragment never leaves the
       browser, so this step can't be driven through Repeater alone) --
       the onerror handler fires and pings /pwn, proving the injected
       markup executed inside the page's own origin and session.
    5. Confirm success: GET /flag using the SAME session cookie the
       browser used for step 4.

Fix: never build DOM content from an untrusted string with innerHTML --
use textContent, or an HTML-sanitizing library, for anything derived from
the URL (search, hash, referrer), postMessage, or any other
client-controlled source.
"""

import hashlib
from flask import Flask, request, session, jsonify

app = Flask(__name__)
app.secret_key = "lab60-not-secret"
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-60-dom-xss").hexdigest()[:16]

PAGE = """<!doctype html>
<html>
<head><title>Welcome</title></head>
<body>
  <h1>Welcome</h1>
  <div id="greeting">Hello, guest!</div>
  <script>
    // VULN: untrusted client-side data (the URL fragment -- never sent to
    // the server) written straight into the DOM with innerHTML.
    document.getElementById('greeting').innerHTML = 'Hello, ' +
      decodeURIComponent(location.hash.replace(/^#name=/, '') || 'guest') + '!';
  </script>
</body>
</html>"""


@app.route("/")
def index():
    session["visited"] = True
    return PAGE


@app.route("/pwn")
def pwn():
    # Reached only if the browser actually ran the injected markup's
    # onerror handler -- i.e. the sink really executed script, not just
    # matched a static pattern.
    session["exploited"] = True
    return ("", 204)


@app.route("/flag")
def flag_route():
    if not session.get("exploited"):
        return jsonify(solved=False,
                        reason="trigger the DOM sink in a real browser first (see walkthrough step 4)"), 403
    return jsonify(solved=True, flag=FLAG)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5060, debug=False)
