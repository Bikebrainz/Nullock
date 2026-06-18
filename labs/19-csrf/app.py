"""
Lab 19 -- Cross-Site Request Forgery (CSRF).

POST /change-email updates the account email with NO anti-CSRF token, and
the session cookie has no SameSite attribute. Any malicious page the
victim visits can auto-submit this form using the victim's cookies.

In Nullock:
    1. nullock scope add http://localhost:5019/*
    2. POST /login (any user), then use /change-email -- captured.
    3. Note: no CSRF token in the request, and the session cookie has no
       SameSite attribute (the header audit flags the cookie).
    4. A cross-site auto-submitting form to /change-email succeeds.

Fix: require a per-session CSRF token on state-changing requests, and set
SameSite=Lax/Strict on the session cookie.
"""

from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "lab19-not-secret"
EMAIL = {"value": "alice@corp.example"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        session["user"] = request.form.get("user", "alice")
        return redirect("/account")
    return '<form method="post"><input name="user" value="alice"><button>login</button></form>'


@app.route("/account")
def account():
    if "user" not in session:
        return redirect("/login")
    return ('email: ' + EMAIL["value"] +
            '<form method="post" action="/change-email">'
            '<input name="email"><button>change</button></form>')


@app.route("/change-email", methods=["POST"])
def change_email():
    if "user" not in session:
        return "login first", 401
    # VULN: state change with no CSRF token.
    EMAIL["value"] = request.form.get("email", "")
    return "email changed to " + EMAIL["value"]


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5019, debug=False)
