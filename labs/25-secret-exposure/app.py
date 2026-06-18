"""
Lab 25 -- Secrets exposed in client assets + a readable .env.

The home page loads /static/app.js, which embeds a hardcoded cloud
credential, and the app also serves /.env with database creds. Both are
client-reachable -- classic secret leakage.

In Nullock:
    1. nullock scope ... add http://localhost:5025/*
    2. nullock secrets http://localhost:5025/   -- flags the AWS key in app.js
    3. nullock exposure http://localhost:5025/  -- flags the readable /.env

Fix: keep secrets server-side, never ship them in JS; block dotfiles at the
web server; rotate anything that leaked.
"""

from flask import Flask, Response

app = Flask(__name__)

# Assembled at runtime so this source file carries no literal key shape.
# (This is AWS's PUBLISHED example key, not a real credential.)
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


@app.route("/")
def index():
    return '<script src="/static/app.js"></script><h1>store</h1>'


@app.route("/static/app.js")
def appjs():
    js = "const cfg = { region: 'us-east-1', awsKey: '" + FAKE_AWS + "' };\n"
    return Response(js, mimetype="application/javascript")


@app.route("/.env")
def dotenv():
    body = ("DB_HOST=db.internal\nDB_USER=admin\n"
            "DB_PASSWORD=hunter2\nSECRET_KEY=changeme\n")
    return Response(body, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5025, debug=False)
