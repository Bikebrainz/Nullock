"""
Lab 44 -- CRLF injection / HTTP response splitting.

A redirect parameter is copied straight into the Location response header
with no CR/LF stripping, so an attacker can smuggle extra headers (or a
whole second response) into the reply -- header injection, cookie fixation,
reflected XSS via an injected body, cache poisoning.

In Nullock:
    1. nullock scope add http://localhost:5044/*
    2. nullock crlf http://localhost:5044/
       -- injects %0d%0a<header> into the redirect params; Nullock confirms
       when its marker header appears as a real header in the response.

Fix: never put raw user input in a header; strip/reject CR and LF, or use
a framework API that rejects them. (Modern WSGI servers reject newlines in
headers -- this lab uses the stdlib http.server precisely because it does
NOT, so the classic bug is reproducible.)
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

REDIRECT_PARAMS = ("url", "next", "redirect", "return", "returnurl",
                   "dest", "goto", "ref", "callback", "page", "lang", "q")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        target = None
        for k in REDIRECT_PARAMS:
            if k in q:
                target = q[k][0]
                break
        if target is not None:
            self.send_response(302)
            self.send_header("Location", target)   # VULN: raw CR/LF passes through
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            body = b"<h1>redirector</h1><p>pass ?url=/somewhere</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 5044), Handler).serve_forever()
