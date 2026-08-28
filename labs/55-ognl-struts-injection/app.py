"""
Lab 55 -- OGNL / Apache Struts2 expression injection (S2-045 / CVE-2017-5638 class).

A Struts2-style greeting banner renders user input through an OGNL
`%{...}` expression tag -- Struts2's own templating syntax for binding a
value expression into markup -- by string concatenation instead of passing
`name` as a bound variable. Anything the attacker wraps in `%{ }` gets
evaluated server-side, from harmless arithmetic all the way up to the
`@java.lang.Runtime@getRuntime().exec(...)` OGNL gadget real Struts2 CVEs
use for RCE. This lab's toy evaluator only understands two OGNL-shaped
forms (arithmetic and a `@exec(...)` call) -- enough to prove the same
injection class without needing a real JVM/OGNL stack -- and, just as
importantly, does NOT evaluate `{{ }}` (Jinja/Twig-style) syntax, so a hit
here fingerprints the OGNL/Struts2 family specifically rather than generic
SSTI.

Run:
    pip install flask
    python app.py

In Nullock:
    1. nullock scope add http://localhost:5055/*
    2. Browse /greet?name=world -- "hello, world!".
    3. Send to Repeater. Change name to: %{7*7}
       Response: "hello, 49!" -- the expression was evaluated, not echoed.
    4. Run the active probe (ssti) against /greet with param=name: it
       sends the polyglot pre%{a*b}sep%{c*d}suf, sees both products with
       the literal separator preserved and neither raw expression echoed,
       and confirms with engines containing "OGNL (Apache Struts2)" --
       and NOT "Jinja2", proving the %{ } family fingerprints this engine
       uniquely.
    5. Escalate to the real-world impact: name to
       %{@exec('id')} -- the response includes the output of `id`, the
       same class of gadget CVE-2017-5638 walks via
       @java.lang.Runtime@getRuntime().exec() to get RCE from a Struts2
       Content-Type header, just reached through a friendlier syntax here.
    6. Confirm success: GET /flag?name=%{@exec('echo $NULLOCK_FLAG')} -- the
       flag lives only in the app's process environment, unreachable except
       by getting the expression to actually execute a command; same
       concatenation /greet uses.

Fix: never concatenate user input into an OGNL/EL expression string. Bind
it as a plain value (Struts2: `<s:property value="name"/>` with `name`
pushed onto the value stack, never into the expression source itself), and
keep the interpreter's reachable object graph away from user control
(Struts2's own fix line for this CVE class: sandbox/allowlist OGNL's
static-method-access to close the Runtime/ProcessBuilder gadgets off).
"""

import hashlib
import os
import re
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-55-ognl-struts-injection").hexdigest()[:16]
# Only reachable via a command actually executed by the @exec(...) gadget --
# a plain Python variable wouldn't be visible to the subprocess's own shell.
os.environ["NULLOCK_FLAG"] = FLAG

_ARITH = re.compile(r"%\{\s*(\d+)\s*\*\s*(\d+)\s*\}")
_EXEC = re.compile(r"%\{@exec\('([^']*)'\)\}")


def render_ognl(template):
    """Toy stand-in for Struts2's %{ } OGNL evaluator: arithmetic proof
    (what the active probe confirms) plus an @exec(...) gadget standing in
    for the real @java.lang.Runtime@getRuntime().exec() RCE chain. Deliberately
    does not touch {{ }} (Jinja-style) syntax at all, so it never fires on
    generic SSTI polyglots -- only on the %{ } family."""
    def run_cmd(m):
        try:
            return subprocess.run(m.group(1), shell=True, capture_output=True,
                                   text=True, timeout=5).stdout.strip()
        except Exception:
            return ""
    template = _EXEC.sub(run_cmd, template)
    template = _ARITH.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), template)
    return template


@app.route("/")
def index():
    return ('<form action="/greet"><input name="name" value="world">'
            '<button>greet</button></form>')


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # VULN: name concatenated straight into the OGNL expression source,
    # the same mistake as Struts2 rendering `%{ }` around raw user input.
    banner = "hello, %s!" % name
    return render_ognl(banner)


@app.route("/flag")
def flag():
    name = request.args.get("name", "world")
    banner = "hello, %s!" % name
    out = render_ognl(banner)
    # Solved only when the flag came out of an actually-executed @exec(...)
    # gadget, not from typing the flag text directly into name.
    if FLAG in out and FLAG not in name:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)
