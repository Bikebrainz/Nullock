"""
Lab 49 -- robots.txt / sitemap leaking hidden attack surface.

robots.txt lists Disallow paths an admin wanted crawlers to skip -- which
is exactly a map of the unlinked, sensitive areas (admin, backups, internal
APIs) for an attacker. The sitemap enumerates still more, including a
"secret-report" page that is never linked from anywhere else on the site.

In Nullock:
    1. nullock scope add http://localhost:5049/*
    2. nullock robots http://localhost:5049/
       -- parses robots.txt + sitemap.xml and surfaces every Disallow path
       as recon (robots-disallowed-path findings).
    3. Confirm success: GET /sitemap.xml (or /robots.txt), then GET
       /secret-report -- content only discoverable via that recon, never
       linked from the homepage. Then GET /flag -- solved only once the
       hidden page was reached AFTER actually reading the map that named
       it, proving real recon rather than a blind guess.

Fix: don't rely on robots.txt/sitemap for security -- they're public. Put
real access control on those paths and don't enumerate secrets in them.
"""

from flask import Flask, Response, jsonify
import hashlib

app = Flask(__name__)
FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-49-robots-disclosure").hexdigest()[:16]

ROBOTS = ("User-agent: *\n"
          "Disallow: /admin-portal/\n"
          "Disallow: /backup/\n"
          "Disallow: /api/internal/\n"
          "Sitemap: http://localhost:5049/sitemap.xml\n")

SITEMAP = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           '  <url><loc>http://localhost:5049/secret-report</loc></url>\n'
           '  <url><loc>http://localhost:5049/staging/</loc></url>\n'
           '</urlset>\n')

READ = {"robots": False, "sitemap": False}
FOUND = {"done": False}


@app.route("/")
def index():
    return "<h1>corp site</h1>"


@app.route("/robots.txt")
def robots():
    READ["robots"] = True
    return Response(ROBOTS, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    READ["sitemap"] = True
    return Response(SITEMAP, mimetype="application/xml")


@app.route("/secret-report")
def secret_report():
    # VULN: unlinked page, discoverable only via the sitemap.
    if READ["sitemap"] or READ["robots"]:
        FOUND["done"] = True
    return "<h1>Q3 internal revenue report -- do not distribute</h1>"


@app.route("/flag")
def flag_route():
    if FOUND["done"]:
        return jsonify(solved=True, flag=FLAG)
    return jsonify(solved=False), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5049, debug=False)
