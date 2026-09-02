"""
Lab 82 -- Excessive data exposure: the profile API returns the whole DB row, the page only ever renders two fields of it.

/profile/<username> looks completely clean in a browser: a username and a
one-line bio, nothing else. That page is rendered from a single fetch to
/api/profile/<username>, and the *handler* behind that endpoint was never
given its own response shape -- it just serializes the full in-memory user
record and lets the frontend pick out whichever fields it feels like
using. Convenient for whoever wrote the frontend, and invisible to anyone
who only ever looks at the rendered page. Anyone who reads the raw HTTP
response instead of the rendered HTML sees passwordHash, mfaSecret,
isAdmin, and lastLoginIp sitting right there in the JSON, for every
profile the endpoint will answer for -- public pages included, no login
required.

This is OWASP API3:2023 (Broken Object Property Level Authorization --
Excessive Data Exposure): distinct from an access-control bug like IDOR
(Lab 04) or BOLA (Lab 80), where the question is WHICH objects you can
reach. Here access to the object is fine and intended -- profiles are
meant to be public -- the bug is that the response carries far more
PROPERTIES of that object than the product ever meant to expose, because
serialization was never scoped down to a public view. A tool that only
ever renders pages like a browser does never notices; one that shows you
the raw wire response does.

In Nullock:
    1. nullock scope add http://localhost:5082/*
    2. Open http://localhost:5082/profile/admin in a browser -- a
       username and a bio, nothing else visible on the page.
    3. In Nullock's Proxy history, find the page's own
       GET /api/profile/admin call and open it in the Inspector /
       DetailPane -- the raw response body is not what the page showed
       you.
    4. Read the passwordHash field straight off that JSON.
    5. Confirm success: GET /flag?hash=<the exact passwordHash value>.

Fix: never serialize an ORM row / internal record straight into an HTTP
response -- define an explicit public view (an allow-list of fields) per
endpoint, and keep secrets (hashes, MFA seeds, internal flags) out of any
response a client-facing endpoint can return, full stop.
"""

import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {
    "alice": {
        "id": 1,
        "username": "alice",
        "bio": "coffee and cats",
        "avatarUrl": "/static/avatars/alice.png",
        "passwordHash": "$2b$12$KJ8x9QwZ1nR7vC3mF6tPeuYlHh8mS0dXeQrA2bT4wN6oC1pL9sE.a",
        "mfaSecret": "JBSWY3DPEHPK3PXP",
        "isAdmin": False,
        "lastLoginIp": "203.0.113.7",
    },
    "admin": {
        "id": 2,
        "username": "admin",
        "bio": "site administrator",
        "avatarUrl": "/static/avatars/admin.png",
        "passwordHash": "$2b$12$9fQeR3mZoT7yXk1vB5cWpuLtNq2dS8hAyF0jC6rE4wK3nP7oI9uDa",
        "mfaSecret": "NBSWY3DPFQQHO33SNRSA",
        "isAdmin": True,
        "lastLoginIp": "10.0.0.4",
    },
}

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-82-excessive-data-exposure").hexdigest()[:16]


@app.route("/profile/<username>")
def profile_page(username):
    user = USERS.get(username)
    if user is None:
        return "not found", 404
    # The page itself only ever reads .username and .bio -- but that's a
    # frontend habit, not a server-side guarantee. See /api/profile below.
    return (
        "<h1>%s</h1><p>%s</p>"
        "<script>fetch('/api/profile/%s').then(r=>r.json())"
        ".then(u=>document.title=u.username)</script>"
        % (user["username"], user["bio"], username)
    )


@app.route("/api/profile/<username>")
def api_profile(username):
    user = USERS.get(username)
    if user is None:
        return jsonify(error="not found"), 404
    # VULN: the whole in-memory record goes out, unfiltered. No public
    # view, no allow-list -- whatever fields the record happens to carry,
    # the response carries too.
    return jsonify(user)


@app.route("/flag")
def flag_route():
    # Solved only by submitting the ACTUAL passwordHash value read off the
    # wire, proving the response was inspected raw rather than guessed.
    hash_ = request.args.get("hash", "")
    if hash_ and hash_ == USERS["admin"]["passwordHash"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5082, debug=False)
