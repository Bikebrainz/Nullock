"""
Lab 13 -- OS command injection in a diagnostics endpoint.

/ping?host=... concatenates the `host` parameter into a shell command and
runs it with shell=True, returning stdout. Shell metacharacters (';', '|',
'$( )', backticks) let you run arbitrary commands.

In Nullock:
    1. nullock scope ... add http://localhost:5013/*
    2. Browse http://localhost:5013/ping?host=localhost
    3. Right-click the captured row -> Send to Repeater
    4. Set host to:  localhost;echo $((6*7))
    5. Fire. The response contains 42 -- the shell evaluated it.
    6. Run the active probe (cmdi): it confirms RCE with an arithmetic
       canary it never sees reflected, only evaluated.

Fix: never pass user input to a shell. Use subprocess with an argument
list (shell=False) and validate the host against a strict pattern.
"""

from flask import Flask, request
import subprocess

app = Flask(__name__)


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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5013, debug=False)
