"""
Lab 49 -- robots.txt / sitemap leaking hidden attack surface.

robots.txt lists Disallow paths an admin wanted crawlers to skip -- which
is exactly a map of the unlinked, sensitive areas (admin, backups, internal
APIs) for an attacker. The sitemap enumerates still more.

In Nullock:
    1. nullock scope add http://localhost:5049/*
    2. nullock robots http://localhost:5049/
       -- parses robots.txt + sitemap.xml and surfaces every Disallow path
       as recon (robots-disallowed-path findings).

Fix: don't rely on robots.txt for security -- it's public. Put real access
control on those paths and don't enumerate secrets in it.
"""

from flask import Flask, Response

app = Flask(__name__)

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


@app.route("/")
def index():
    return "<h1>corp site</h1>"


@app.route("/robots.txt")
def robots():
    return Response(ROBOTS, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    return Response(SITEMAP, mimetype="application/xml")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5049, debug=False)
