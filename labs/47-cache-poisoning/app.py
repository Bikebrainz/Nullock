"""
Lab 47 -- Web cache poisoning via an unkeyed header.

The page reflects the X-Forwarded-Host header into an absolute URL and is
served with a shared-cacheable Cache-Control. X-Forwarded-Host is not part
of the cache key, so an attacker can poison the cached copy (e.g. point the
canonical / asset URL at their host) for every later visitor.

In Nullock:
    1. nullock scope add http://localhost:5047/*
    2. nullock cachepoison http://localhost:5047/
       -- injects X-Forwarded-Host and confirms it reflects into a cacheable
       response (the poisoning primitive).
    3. Confirm success: GET / with header "X-Forwarded-Host: evil.example"
       -- the canonical link reflects evil.example into a still-cacheable
       response. Then GET /flag -- solved only once an attacker-controlled
       (non-default) host was actually reflected, proving the poisoning
       primitive, not just that the header is echoed back verbatim.

Fix: don't reflect untrusted headers into responses; if you must, add them
to the cache key (Vary) or strip them at the edge.
"""

from flask import Flask, request, make_response, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-47-cache-poisoning").hexdigest()[:16]
POISONED = {"done": False}


@app.route("/")
def index():
    host = request.headers.get("X-Forwarded-Host", request.host)
    if "X-Forwarded-Host" in request.headers and host != request.host:
        # VULN confirmed: an attacker-controlled, unkeyed header reached a
        # still-cacheable response.
        POISONED["done"] = True
    # VULN: an unkeyed request header reflected into a cacheable response.
    resp = make_response(
        '<link rel="canonical" href="https://%s/"><h1>welcome</h1>' % host)
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


@app.route("/flag")
def flag_route():
    if POISONED["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5047, debug=False)
