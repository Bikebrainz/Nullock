"""
Lab 34 -- 2FA bypass (protected page never checks the 2FA flag).

Login sets session["user"]; the /verify step is supposed to set
session["mfa"]=True, but /dashboard only checks that you're logged in --
not that 2FA completed -- so you can skip /verify entirely.

In Nullock:
    1. nullock scope add http://localhost:5034/*
    2. POST /login user=alice (you now have a session, mfa=false).
    3. GET /dashboard directly -- it loads WITHOUT completing 2FA.

Fix: gate sensitive pages on BOTH session["user"] AND session["mfa"]; fail
closed when the 2FA step hasn't been completed.
"""

from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "lab34-not-secret"


@app.route("/")
def index():
    return '<a href="/login">login</a>'


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        session["user"] = request.form.get("user", "alice")
        session["mfa"] = False
        return redirect("/verify")
    return ('<form method="post"><input name="user" value="alice">'
            '<button>login</button></form>')


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        # (the real OTP check would live here)
        session["mfa"] = True
        return redirect("/dashboard")
    return ('<form method="post"><input name="otp" placeholder="6-digit code">'
            '<button>verify</button></form>')


@app.route("/dashboard")
def dashboard():
    # VULN: checks login but NOT session["mfa"].
    if "user" not in session:
        return redirect("/login")
    return "sensitive dashboard for %s (mfa=%s)" % (session["user"], session.get("mfa"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5034, debug=False)
