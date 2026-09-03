"""
Lab 88 -- YAML unsafe deserialization (CI config import -> RCE).

A pipeline-config importer accepts a YAML file and parses it with
`yaml.load(raw, Loader=yaml.Loader)`. The developer thought passing an
explicit Loader (instead of the bare `yaml.load(raw)` that newer PyYAML
warns about) made this safe. It didn't: `yaml.Loader` (an alias for
`yaml.UnsafeLoader`) still honours `!!python/object/apply:` tags, which
call ANY importable Python callable by dotted name with attacker-chosen
arguments at parse time -- full code execution before the app ever looks
at the "config".

Distinct from Lab 10 (pickle -- a binary blob whose opcodes are
Turing-complete by design, no text format involved) and Lab 07 (Jinja2
SSTI -- a template-rendering sink, not a deserializer): here the format
LOOKS like inert structured data (the kind every CI system ingests) and
the unsafe call happens inside a library most developers assume is just
"the YAML parser", with a same-named safe sibling (`yaml.safe_load`) one
argument away.

In Nullock:
    1. GET / -- shows the importer's documented config shape (name,
       steps: [...]) and confirms POST /config/import is the ingest path.
    2. POST /config/import with a normal YAML body (see the sample at
       GET /) -- 200, echoes the parsed step count. Looks completely
       ordinary.
    3. POST /config/import with:
         !!python/object/apply:os.system ["id > /tmp/nullock-lab88-pwned"]
       -- 200 again (same shape response), but the server just ran that
       shell command while "parsing" your config. `nullock deser
       http://127.0.0.1:5088/config/import` flags this with its
       well-formed-vs-malformed differential: a benign YAML doc parses
       clean, a `!!python/object/apply:` doc either errors under a
       hardened parser or silently succeeds while doing something a
       parser never should -- the signature this lab's malformed leg
       trips.
    4. Confirm success without touching a shell: POST /config/import
       with:
         !!python/object/apply:__main__._mark_pwned []
       which calls the app's own in-process no-op marker instead of a
       real command -- same reachable-arbitrary-call primitive as step
       3, aimed somewhere harmless. Then GET /flag.
    5. The fix: `yaml.safe_load(raw)` (or `yaml.load(raw,
       Loader=yaml.SafeLoader)`). SafeLoader only ever constructs plain
       dict/list/str/int/etc -- no `!!python/object` tag of any kind is
       honoured, so there is no dotted-name-to-callable path at all.
       `yaml.FullLoader` is a half-measure: it blocks `python/object/apply`
       specifically but still builds arbitrary Python objects, which is
       enough for gadget chains in some codebases -- SafeLoader is the
       only loader with no code-execution surface.
"""

from flask import Flask, request, jsonify
import yaml

app = Flask(__name__)
FLAG = "NULLOCK{yaml_unsafe_load_rce_88}"

SAMPLE_CONFIG = "name: deploy\nsteps:\n  - build\n  - test\n  - publish\n"

STATE = {"last_step_count": 0, "pwned": False}


def _mark_pwned():
    # Deliberately harmless -- the reachable-arbitrary-call is the
    # vulnerability being proven, not what gets called.
    STATE["pwned"] = True
    return "pwned"


@app.route("/")
def index():
    return jsonify(
        importer="CI config import",
        endpoint="POST /config/import",
        content_type="application/x-yaml (raw body)",
        sample_config=SAMPLE_CONFIG,
    )


@app.route("/config/import", methods=["POST"])
def config_import():
    raw = request.get_data(as_text=True)
    try:
        # VULN: yaml.Loader (== yaml.UnsafeLoader) honours
        # !!python/object/apply: tags -- arbitrary callable, arbitrary
        # args, at parse time. yaml.safe_load(raw) would be safe here.
        doc = yaml.load(raw, Loader=yaml.Loader)
    except Exception as e:
        return jsonify(error=str(e)), 400

    steps = doc.get("steps", []) if isinstance(doc, dict) else []
    STATE["last_step_count"] = len(steps)
    return jsonify(imported=True, name=(doc or {}).get("name") if isinstance(doc, dict) else None, step_count=len(steps))


@app.route("/status")
def status():
    return jsonify(last_step_count=STATE["last_step_count"])


@app.route("/reset", methods=["POST", "GET"])
def reset():
    STATE["last_step_count"] = 0
    STATE["pwned"] = False
    return jsonify(reset=True)


@app.route("/flag")
def flag():
    if STATE["pwned"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5088, debug=False)
