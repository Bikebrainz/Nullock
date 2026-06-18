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

Fix: don't reflect untrusted headers into responses; if you must, add them
to the cache key (Vary) or strip them at the edge.
"""

from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/")
def index():
    host = request.headers.get("X-Forwarded-Host", request.host)
    # VULN: an unkeyed request header reflected into a cacheable response.
    resp = make_response(
        '<link rel="canonical" href="https://%s/"><h1>welcome</h1>' % host)
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5047, debug=False)
