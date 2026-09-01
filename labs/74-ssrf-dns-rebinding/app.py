"""
Lab 74 -- SSRF via DNS rebinding (validate-then-fetch TOCTOU).

/fetch?url=... is NOT naively open like Lab 40, and it isn't fooled by a
bare loopback URL either: it resolves the URL's hostname, rejects the
request outright if that IP is private/loopback/link-local, and only then
goes on to fetch it. GET /fetch?url=http://127.0.0.1:5074/... gets a clean
400 "blocked" -- the filter does exactly what it looks like it does.

The bug is WHEN it resolves. The check calls `_resolve(host)` once to
decide whether to allow the request; the fetch step then reconnects by
hostname and lets `_resolve(host)` run AGAIN to get the IP to actually
connect to. Nothing pins the fetch to the IP the check just approved. A
name whose DNS answer changes between those two lookups -- the classic
"rebinding" attack, where an attacker-controlled nameserver serves a
public IP with a near-zero TTL, then flips to an internal IP once that TTL
expires -- sails straight through: the check resolves it once and sees the
public answer, the fetch resolves it again a moment later and gets the
internal one.

This lab collapses the real attack's timing race (wait for the TTL to
expire between two real DNS lookups) into something reproducible without
a real internet-facing nameserver: `_resolve()` special-cases one hostname,
`rebind.lab74.test`, to answer with a public-looking IP on its FIRST call
per process and with 127.0.0.1 on every call after that -- same
"first answer differs from every later answer" shape a real rebind
produces, without the TTL wait or your own DNS infrastructure. Every other
hostname resolves normally.

Nullock's automated SSRF prober (`/api/ssrf/test`) sends one request and
inspects one response; it has no way to force two independent resolutions
of the same host with different answers, so -- like Lab 70's scheme gap --
this is a Repeater find: send /fetch to Repeater, point `url` at the
rebind hostname, and watch the SAME request that would 400 for a literal
127.0.0.1 come back 200 once the hostname is the thing doing the flipping.

In Nullock:
    1. nullock scope add http://localhost:5074/*
    2. GET /fetch?url=http://127.0.0.1:5074/internal/admin-secret -- 400
       "blocked": the private/loopback filter does work against a literal
       loopback IP.
    3. Send /fetch to Repeater, change url to
       http://rebind.lab74.test:5074/internal/admin-secret -- the
       VALIDATION lookup for this host returns 8.8.8.8 (public, allowed);
       the FETCH step then resolves the same name again, this time getting
       127.0.0.1, and connects there instead -- the response comes back
       200 with the internal secret.
    4. Confirm success: GET /flag -- solved only once /fetch's own
       server-side request chain (not a direct hit on /internal) actually
       returned the internal marker.

Fix: resolve once, validate that IP, and connect to the VALIDATED IP
address directly (never the hostname again) -- pinning the connection to
the address you checked is what defeats a DNS answer that changes between
your two lookups.
"""

import hashlib
import ipaddress
import socket
from urllib.parse import urlparse

from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-74-ssrf-dns-rebinding").hexdigest()[:16]
PORT = 5074
REBIND_HOST = "rebind.lab74.test"
_rebind_calls = {"n": 0}
SSRF_HIT = {"done": False}


def _resolve(host):
    # VULN lives in how the caller USES this, not in the function itself:
    # the same hostname is allowed to answer differently across two calls.
    if host == REBIND_HOST:
        n = _rebind_calls["n"]
        _rebind_calls["n"] = n + 1
        return "8.8.8.8" if n == 0 else "127.0.0.1"
    return socket.gethostbyname(host)


def _is_public(ip):
    addr = ipaddress.ip_address(ip)
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


def _raw_get(ip, port, host_header, path):
    with socket.create_connection((ip, port), timeout=3) as s:
        req = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host_header)
        s.sendall(req.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.split(b"\r\n\r\n", 1)[-1].decode("utf-8", errors="replace")


@app.route("/")
def index():
    return (
        '<a href="/fetch?url=http://rebind.lab74.test:5074/">fetch a URL</a><br>'
        "blocked direct hit: /fetch?url=http://127.0.0.1:5074/internal/admin-secret"
    )


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme != "http" or not parsed.hostname:
        return jsonify(error="http:// url with a host required"), 400
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        check_ip = _resolve(host)
    except socket.gaierror:
        return jsonify(error="dns lookup failed"), 502
    if not _is_public(check_ip):
        return jsonify(error="blocked: %s resolves to a non-public address" % host), 400
    try:
        # VULN: re-resolves `host` instead of connecting to check_ip, the
        # address it just validated above.
        fetch_ip = _resolve(host)
        body = _raw_get(fetch_ip, port, host, path)
    except OSError as e:
        return jsonify(error=str(e)), 502
    if "lab74-admin-secret-marker" in body:
        SSRF_HIT["done"] = True
    return body, 200, {"Content-Type": "text/plain"}


@app.route("/internal/admin-secret")
def admin_secret():
    return "lab74-admin-secret-marker -- internal admin panel, not meant to be reachable from /fetch\n"


@app.route("/flag")
def flag():
    if SSRF_HIT["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False, hint="a direct hit on /internal isn't enough -- it has to come back through /fetch"), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
