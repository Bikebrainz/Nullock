"""
Lab 48 -- Sensitive file exposure (.env / .git / config backups).

Deployment leftovers are served straight from the web root: a .env with
live secrets, the .git/ metadata (full source + history), and a *.bak
config. Each is fetchable by anyone who guesses the path.

In Nullock:
    1. nullock scope add http://localhost:5048/*
    2. nullock exposure http://localhost:5048/
       -- probes curated sensitive paths and confirms each by content
       signature (sensitive-file-exposure findings).
    3. Confirm success: fetch at least two of /.env, /.git/config,
       /.git/HEAD, /wp-config.php.bak, then GET /flag -- solved only once
       more than one distinct leftover was actually retrieved, proving a
       real exposure sweep rather than one lucky guess.

Fix: never deploy .env/.git/backups under the web root; block dotfiles and
*.bak at the server; keep secrets out of the document root entirely.
"""

from flask import Flask, Response, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-48-sensitive-file-exposure").hexdigest()[:16]

ENV = ("DB_HOST=db.internal\n"
       "DB_USER=app\n"
       "DB_PASSWORD=hunter2\n"
       "SECRET_KEY=devsecret\n")
GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
GIT_HEAD = "ref: refs/heads/main\n"
WP_BAK = "<?php\ndefine('DB_NAME', 'wp');\ndefine('DB_PASSWORD', 'hunter2');\n"

FETCHED = set()


@app.route("/")
def index():
    return "<h1>blog</h1>"


@app.route("/.env")
def env():
    FETCHED.add("env")
    return Response(ENV, mimetype="text/plain")


@app.route("/.git/config")
def gitconfig():
    FETCHED.add("gitconfig")
    return Response(GIT_CONFIG, mimetype="text/plain")


@app.route("/.git/HEAD")
def githead():
    FETCHED.add("githead")
    return Response(GIT_HEAD, mimetype="text/plain")


@app.route("/wp-config.php.bak")
def wpbak():
    FETCHED.add("wpbak")
    return Response(WP_BAK, mimetype="text/plain")


@app.route("/flag")
def flag_route():
    if len(FETCHED) >= 2:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5048, debug=False)
