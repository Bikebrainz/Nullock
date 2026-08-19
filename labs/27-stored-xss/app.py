"""
Lab 27 -- Stored (persistent) XSS in a comment feed.

POST /comment stores a comment; GET / renders every comment into the page
WITHOUT escaping, so a comment containing <script> executes for every later
visitor.

In Nullock:
    1. nullock scope add http://localhost:5027/*
    2. POST /comment  text=<script>alert(document.domain)</script>
    3. GET / -- the script is served inline and runs for all visitors.
    4. Confirm success: GET /flag -- solved only once a stored comment
       actually contains an unescaped <script> tag; escaped output would
       render it as harmless text and never match.

Fix: escape on output (Jinja autoescape / markupsafe) or sanitize HTML with
an allow-list; add a strict CSP as defense in depth.
"""

from flask import Flask, request, redirect, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-27-stored-xss").hexdigest()[:16]
COMMENTS = []


@app.route("/")
def index():
    items = "".join("<li>" + c + "</li>" for c in COMMENTS)   # VULN: raw render
    return ('<h1>comments</h1><ul>' + items + '</ul>'
            '<form method="post" action="/comment">'
            '<input name="text"><button>post</button></form>')


@app.route("/comment", methods=["POST"])
def comment():
    COMMENTS.append(request.form.get("text", ""))
    return redirect("/")


@app.route("/flag")
def flag_route():
    if any("<script" in c.lower() for c in COMMENTS):
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5027, debug=False)
