"""
Lab 78 -- SSRF into an internal Docker Engine API (unauthenticated control-plane exposure).

/fetch?url=... previews a webhook target server-side. Its blocklist rejects
one host: "169.254.169.254", the well-known cloud-metadata IP every SSRF
checklist tells you to defend. It never considers the OTHER thing loopback
gives an attacker who can make the server issue arbitrary requests: this
host also runs an unauthenticated Docker Engine API on 127.0.0.1:2375 --
the default `dockerd -H tcp://0.0.0.0:2375` misconfiguration (no TLS, no
auth token), a real and still-common finding on CI runners and dev boxes,
not a lab invention. /fetch's blocklist has nothing to say about it.

This is a different angle from every earlier SSRF lab here: 05's total
absence of filtering, 40's same-process "INTERNAL SECRET" text, 64/65's
redirect/second-fetch-path pivots, 70's scheme blind spot, 72's blind/OAST-
only confirmation, 74's TOCTOU race, 75's numeric-encoding bypass, 76's
CORS-adjacent null-origin case -- here the blocklist isn't buggy or bypassed
at all, it just protects the ONE target (cloud metadata) everyone remembers
and leaves the whole rest of the loopback control-plane surface open. It's
also the first SSRF lab whose "internal" service reproduces a REAL fixed
banner Nullock's dedicated SSRF prober already fingerprints by name:
ssrf_scan.cpp's `kProbes` table carries an `internal-docker` entry for
exactly `http://127.0.0.1:2375/version` containing `"ApiVersion"` (alongside
sibling entries for Elasticsearch on :9200, Spring Actuator on :8080, and
Consul on :8500) -- unlike Lab 75, where the prober's own blind spot forces
a manual bypass, THIS lab's finding is one the automated `/api/ssrf/test`
confirms outright, no hand-crafted encoding required.

In Nullock:
    1. nullock scope add http://localhost:5078/*
    2. GET /fetch?url=http://169.254.169.254/latest/meta-data/ -- 400
       "blocked host": the one host the blocklist actually defends.
    3. GET /fetch?url=http://127.0.0.1:2375/version -- 200, and the body IS
       the Docker Engine's own `/version` response: "ApiVersion", "Os":
       "linux", a real kernel string. The blocklist never even considered
       this host.
    4. Pivot further: GET /fetch?url=http://127.0.0.1:2375/containers/json
       lists the host's running containers by name and image -- exactly the
       kind of control-plane inventory an attacker uses to plan the next
       step of a real internal-network pivot.
    5. Or just run the TESTS tab's SSRF check (`/api/ssrf/test`, param=url)
       against /fetch directly -- its built-in `internal-docker` probe hits
       step 3's exact URL/signature pair and confirms with no manual work.
    6. Confirm success: GET /flag -- solved only once /fetch's own
       SERVER-SIDE request actually reached the Docker API and got the real
       "ApiVersion" banner back (not just that :2375 was requested by hand).

Fix: default-deny outbound fetches to loopback/link-local/RFC1918 ranges
(not just the one cloud-metadata address), and separately, never expose
the Docker Engine API without TLS + client-cert auth in the first place --
CIS Docker Benchmark 2.1 exists for exactly this misconfiguration.

(Needs `requests`, which is the labs' only non-Flask dependency.)
"""

import hashlib
import threading
from urllib.parse import urlparse

from flask import Flask, jsonify, request
import requests

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-78-ssrf-internal-docker-api").hexdigest()[:16]
SSRF_HIT = {"done": False}

# VULN: this only ever defends the one host every SSRF checklist names.
# Loopback (where the Docker API below actually lives) is never checked.
BLOCKED_HOSTS = {"169.254.169.254"}


@app.route("/")
def index():
    return '<a href="/fetch?url=http://example.com/">preview a webhook URL</a>'


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "url required", 400
    host = urlparse(url).hostname or ""
    if host in BLOCKED_HOSTS:
        return "blocked host (cloud metadata)", 400
    try:
        r = requests.get(url, timeout=3)
        if '"ApiVersion"' in r.text:
            SSRF_HIT["done"] = True
        return "fetched %d bytes:\n%s" % (len(r.text), r.text[:800])
    except Exception as e:
        return "error: %s" % e, 502


# ---- Internal-only Docker Engine API mock -- same fixed port (2375) and
# response shape as a real unauthenticated dockerd, and the same signal
# Nullock's ssrf_scan.cpp `internal-docker` probe already looks for.
docker_api = Flask("docker-engine-mock")


@docker_api.route("/version")
def docker_version():
    return jsonify({
        "Platform": {"Name": ""},
        "Version": "24.0.7",
        "ApiVersion": "1.43",
        "Os": "linux",
        "Arch": "amd64",
        "KernelVersion": "5.15.0-generic",
    })


@docker_api.route("/containers/json")
def docker_containers():
    return jsonify([{
        "Id": "3f2a9c1e8b7d",
        "Names": ["/billing-worker"],
        "Image": "billing-worker:latest",
        "Labels": {"env": "prod"},
    }])


@app.route("/flag")
def flag_route():
    if SSRF_HIT["done"]:
        return jsonify({"solved": True, "flag": FLAG})
    return jsonify({"solved": False})


if __name__ == "__main__":
    threading.Thread(
        target=lambda: docker_api.run(host="127.0.0.1", port=2375,
                                       debug=False, use_reloader=False),
        daemon=True,
    ).start()
    app.run(host="0.0.0.0", port=5078, debug=False)
