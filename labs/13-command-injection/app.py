"""
Lab 13 -- OS command injection in a diagnostics endpoint.

/ping?host=... concatenates the `host` parameter into a shell command and
runs it with shell=True, returning stdout. Shell metacharacters (';', '|',
'$( )', backticks) let you run arbitrary commands.

In Nullock:
    1. nullock scope add http://localhost:5013/*
    2. Browse http://localhost:5013/ping?host=localhost
    3. Right-click the captured row -> Send to Repeater
    4. Set host to:  localhost;echo $((6*7))
    5. Fire. The response contains 42 -- the shell evaluated it.
    6. Run the active probe (cmdi): it confirms RCE with an arithmetic
       canary it never sees reflected, only evaluated.
    7. Confirm success: GET /flag?host=localhost;echo $((6*7)) -- same
       shell=True concatenation /ping uses; hands back the flag once the
       shell actually evaluated the arithmetic (not just echoed digits
       you typed).

Fix: never pass user input to a shell. Use subprocess with an argument
list (shell=False) and validate the host against a strict pattern.
"""

import hashlib
from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-13-command-injection").hexdigest()[:16]


@app.route("/")
def index():
    return ('<form action="/ping"><input name="host" value="localhost">'
            '<button>ping</button></form>')


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # VULN: host concatenated into a shell command string.
    out = subprocess.run("echo pinging " + host, shell=True,
                         capture_output=True, text=True, timeout=5).stdout
    return "<pre>" + out + "</pre>"


@app.route("/flag")
def flag():
    host = request.args.get("host", "localhost")
    # Same shell=True concatenation as /ping.
    out = subprocess.run("echo pinging " + host, shell=True,
                         capture_output=True, text=True, timeout=5).stdout
    # Solved only when "42" came from shell evaluation ($((6*7))), not
    # from typing the literal digits into host -- proves execution.
    if "42" in out and "42" not in host:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5013, debug=False)
