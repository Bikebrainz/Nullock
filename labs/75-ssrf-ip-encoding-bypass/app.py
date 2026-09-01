"""
Lab 75 -- SSRF via IP-address encoding: a host blocklist that only ever compares literal strings.

/fetch?url=... is "protected" against SSRF: it parses the URL and rejects any
request whose HOST string is exactly "127.0.0.1", "localhost", or
"169.254.169.254" -- the usual loopback/cloud-metadata blocklist, and it DOES
work: /fetch?url=http://127.0.0.1:5075/internal/admin-secret comes back 400.

But the check never normalizes the host before comparing it -- it just tests
`host in BLOCKED_HOSTS` on whatever string urlparse() pulled out of the URL.
glibc's resolver (which is what Python's socket module, and therefore
`requests`, ultimately calls into) accepts several other textual spellings of
the exact same IPv4 address that a browser's address bar would also happily
follow:

  - decimal:        http://2130706433/          (127.0.0.1 as one 32-bit int)
  - octal:           http://0177.0.0.1/          (leading-zero octet)
  - hex:             http://0x7f000001/          (whole address as one hex int)
  - short form:      http://127.1/               (trailing zero octets dropped)

None of those strings equal "127.0.0.1", so the blocklist -- which only ever
does an exact string comparison -- lets every one of them straight through.
The fetch then resolves to 127.0.0.1 exactly the same as the literal form
would have, and lands on the internal-only endpoint the blocklist exists to
protect.

This is a different failure mode from every earlier SSRF lab here (05's total
absence of filtering, 40's metadata-endpoint framing, 64's redirect pivot,
65's second unguarded fetch path, 70's scheme blind spot, 72's blind/OAST-only
confirmation, 74's validate-then-fetch TOCTOU): here the host check runs
against the SAME address, at the SAME time as the fetch, with no race and no
alternate code path -- the bug is purely that "is this the blocked host" was
implemented as a literal string comparison against an address family that has
more than one valid spelling.

Nullock's automated SSRF prober (`/api/ssrf/test`) only ever tries the
literal strings "169.254.169.254" and "127.0.0.1" as candidate hosts (see
ssrf_scan.cpp's CANDIDATES table) -- against THIS lab's blocklist those
literal probes correctly get blocked, so the automated probe reports no
finding here. This bug sits in the prober's own blind spot (it does not try
alternate numeric encodings of the same address) and is found in Repeater
by hand instead, same precedent as Lab 70's file:// scheme bypass.

In Nullock:
    1. nullock scope add http://localhost:5075/*
    2. GET /fetch?url=http://127.0.0.1:5075/internal/admin-secret -- 400
       "blocked host": the literal-string blocklist does work for the literal
       spelling.
    3. Send /fetch to Repeater and change url to
       http://2130706433:5075/internal/admin-secret (127.0.0.1 written as one
       decimal integer). "2130706433" is not in BLOCKED_HOSTS, so the check
       passes -- and the fetch itself resolves that same integer straight to
       127.0.0.1, returning the internal secret with a 200.
    4. Octal (http://0177.0.0.1:5075/...), hex (http://0x7f000001:5075/...),
       and short-form (http://127.1:5075/...) all work the same way -- try
       any of them.
    5. Confirm success: GET /flag?url=<same encoded-host URL> -- same fetch
       function /fetch uses, solved only once the marker actually came back
       through a NON-literal encoding of the blocked address (the literal
       127.0.0.1 form is accepted by /fetch's normal flow but does not solve
       /flag, since it never bypassed anything).

Fix: canonicalize the host BEFORE comparing it -- resolve/parse it to its
actual numeric address (e.g. `ipaddress.ip_address(socket.gethostbyname(host))`)
and compare THAT against the blocked address set, instead of comparing
whatever string spelling happened to arrive in the URL.
"""

import hashlib
import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-75-ssrf-ip-encoding-bypass").hexdigest()[:16]
BLOCKED_HOSTS = {"127.0.0.1", "localhost", "169.254.169.254"}


def _blocked(url):
    host = (urlparse(url).hostname or "")
    # VULN: exact string comparison only -- "2130706433", "0177.0.0.1",
    # "0x7f000001", and "127.1" all resolve to 127.0.0.1 but none of them
    # equal the literal string "127.0.0.1", so none of them match here.
    return host in BLOCKED_HOSTS or host.endswith(".internal")


def _is_literal_blocked_spelling(url):
    # Used only by /flag to tell "reached it via the literal spelling" (not a
    # bypass -- /fetch already allows this to fail, it's just not the bug)
    # apart from "reached it via a non-literal encoding of the same address"
    # (the actual SSRF-filter-bypass this lab is about).
    return (urlparse(url).hostname or "") in BLOCKED_HOSTS


def _resolves_to_blocked(url):
    host = urlparse(url).hostname or ""
    try:
        resolved = socket.gethostbyname(host)
        addr = ipaddress.ip_address(resolved)
    except (OSError, ValueError):
        return False
    return resolved in BLOCKED_HOSTS or addr.is_loopback or addr.is_link_local


def _do_fetch(url):
    r = requests.get(url, timeout=3)
    return r.text


@app.route("/")
def index():
    return (
        '<a href="/fetch?url=http://example.com/">fetch a URL</a><br>'
        "blocked direct hit: /fetch?url=http://127.0.0.1:5075/internal/admin-secret<br>"
        "try instead: /fetch?url=http://2130706433:5075/internal/admin-secret"
    )


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="missing url"), 400
    if _blocked(url):
        return jsonify(error="blocked host"), 400
    try:
        return _do_fetch(url), 200, {"Content-Type": "text/plain"}
    except Exception as e:
        return jsonify(error=str(e)), 502


@app.route("/internal/admin-secret")
def internal_secret():
    # Stand-in for an internal-only admin service the blocklist exists to
    # keep unreachable from outside this process.
    return "lab75-secret-marker -- internal admin config, never meant to be network-reachable", 200, {"Content-Type": "text/plain"}


@app.route("/flag")
def flag():
    url = request.args.get("url", "")
    if not url or _blocked(url):
        return jsonify(solved=False), 403
    if _is_literal_blocked_spelling(url):
        return jsonify(solved=False, hint="that's the literal spelling the blocklist already stops -- find one it doesn't"), 403
    if not _resolves_to_blocked(url):
        return jsonify(solved=False, hint="that host doesn't resolve to the blocked address at all"), 403
    try:
        body = _do_fetch(url)
    except Exception:
        return jsonify(solved=False), 403
    if "lab75-secret-marker" in body:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5075, debug=False)
