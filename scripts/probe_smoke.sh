#!/usr/bin/env bash
# Deterministic active-probe regression for Nullock.
#
# Unlike validate_v3.ps1 (PowerShell + Start-Job HttpListener mocks, flaky in PS
# 5.1) this drives the headless control server against reliable Python
# http.server mocks, so it runs the same everywhere (git-bash on Windows, Linux
# CI). It covers the probes that otherwise have only the CVE-DB / enricher unit
# suites for coverage: server-side prototype pollution, host-header injection,
# LDAP injection, and HTTP/3 detection. Each probe is checked for a TRUE hit on
# a vulnerable mock AND no false positive on a safe mock.
#
# Usage:  scripts/probe_smoke.sh [path-to-NullockApp(.exe)]
# Exit:   0 = all assertions passed, non-zero otherwise.
#
# Requires: python3, curl, and a built NullockApp with its Qt DLLs alongside it
# (the default Release build dir already has them deployed).

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXE="${1:-}"
if [ -z "$EXE" ]; then
  for c in "$ROOT/Build/Src/App/Release/NullockApp.exe" \
           "$ROOT/Build/Src/App/NullockApp" \
           "$ROOT/build/Src/App/NullockApp"; do
    [ -x "$c" ] && { EXE="$c"; break; }
  done
fi
[ -n "$EXE" ] && [ -x "$EXE" ] || { echo "FATAL: NullockApp not found; pass its path as arg 1"; exit 2; }

MOCK="$(mktemp /tmp/nullock-probe-mock.XXXXXX.py)"
cat > "$MOCK" <<'PY'
import http.server, socketserver, sys, threading, time, json, gzip, re
import urllib.request, socket, struct, hashlib, base64, hmac
from urllib.parse import urlparse, parse_qs
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
# Shared with the JWT test harness below -- a strong HS256 secret NOT in the
# probe's crack wordlist, so only the deliberately-weak mock is crackable.
JWT_STRONG = 'Zx9-strong-test-secret-not-in-any-wordlist-8f3a1b2c'
# RS256->HS256 confusion modeling (python stdlib has no RSA): the "valid RS256
# signature" is a fixed placeholder the mock accepts, and the confusion bug is
# modeled as HMAC-verifying with the public-key bytes (matches the probe forge).
JWT_FAKE_RSSIG = 'ZmFrZXJzc2lnbmF0dXJlMTIz'
JWT_FAKE_PUBKEY = 'nullock-fake-rsa-public-key-for-confusion-test'
def _b64u_dec(s):
    s += '=' * (-len(s) % 4)
    try: return base64.urlsafe_b64decode(s.encode())
    except Exception: return b''
def _b64u_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def jwt_check(token, secret):
    # returns (sig_valid, alg). alg=='none' flags the alg:none case.
    parts = token.split('.')
    if len(parts) < 2: return (False, '')
    try: alg = json.loads(_b64u_dec(parts[0]).decode('utf-8', 'replace')).get('alg', '')
    except Exception: return (False, '')
    if alg.lower() == 'none': return (False, 'none')
    if len(parts) < 3 or not parts[2]: return (False, alg)
    want = hmac.new(secret.encode(), (parts[0] + '.' + parts[1]).encode(),
                    hashlib.sha256).digest()
    return (_b64u_dec(parts[2]) == want, alg)   # byte compare, like a real verifier
def fire_dns(qname, server, port):
    # Minimal UDP A-query -- simulates a vulnerable JNDI resolver looking up the
    # Log4Shell callback host, landing the token on Nullock's DNS sink.
    try:
        pkt = struct.pack('>HHHHHH', 0x1337, 0x0100, 1, 0, 0, 0)
        for lab in qname.split('.'):
            b = lab.encode()[:63]; pkt += struct.pack('B', len(b)) + b
        pkt += b'\x00' + struct.pack('>HH', 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
        s.sendto(pkt, (server, port))
        try: s.recvfrom(512)
        except Exception: pass
        s.close()
    except Exception: pass
def make(mode):
    state = {'spaces': 0}
    class H(http.server.BaseHTTPRequestHandler):
        def _send(self, code, body, ctype='text/html', extra=None):
            self.send_response(code); self.send_header('Content-Type', ctype)
            for k, v in (extra or []): self.send_header(k, v)
            self.send_header('Content-Length', str(len(body))); self.end_headers()
            self.wfile.write(body)
        def do_POST(self):
            n = int(self.headers.get('Content-Length', '0') or 0)
            raw = self.rfile.read(n) if n else b''
            if mode == 'verb-case':   # POST denied too; only lower-cased "get" flips
                self._send(403, b'<html>x</html>'); return
            if mode.startswith('race-'):
                # Single-threaded TCPServer handles the burst SERIALLY, so a
                # counter is deterministic. race-vuln leaks (first 3 win, rest
                # 409 Conflict); race-atomic grants exactly 1 (rest 409);
                # race-overgrant has no limit (every write wins); race-noise
                # returns 200 then UNRELATED 403 (not a contention status -> must
                # NOT read as a race, the rejection-bucket FP fix).
                st = state.setdefault('race', {'n': 0}); st['n'] += 1; rn = st['n']
                if mode == 'race-vuln':
                    self._send(200 if rn <= 3 else 409, b'ok' if rn <= 3 else b'conflict'); return
                if mode == 'race-atomic':
                    self._send(200 if rn <= 1 else 409, b'ok' if rn <= 1 else b'conflict'); return
                if mode == 'race-overgrant':
                    self._send(200, b'ok'); return
                if mode == 'race-noise':
                    self._send(200 if rn <= 3 else 403, b'ok' if rn <= 3 else b'forbidden'); return
                self._send(200, b'ok'); return
            if mode == 'sspp-vuln':
                try: p = json.loads(raw)
                except Exception: p = {}
                if isinstance(p, dict) and isinstance(p.get('__proto__'), dict) and 'json spaces' in p['__proto__']:
                    try: state['spaces'] = int(p['__proto__']['json spaces'])
                    except Exception: pass
            if mode == 'sspp-ctor':
                # Merge guard BLOCKS the literal __proto__ key but still walks the
                # ordinary constructor->prototype own keys -- the classic
                # __proto__-only-blacklist bypass. Only the constructor.prototype
                # pollute should reformat responses here.
                try: p = json.loads(raw)
                except Exception: p = {}
                if isinstance(p, dict):
                    cp = p.get('constructor')
                    if isinstance(cp, dict) and isinstance(cp.get('prototype'), dict) \
                       and 'json spaces' in cp['prototype']:
                        try: state['spaces'] = int(cp['prototype']['json spaces'])
                        except Exception: pass
            if mode.startswith('xxe'):
                # Vulnerable mock "resolves" an external entity to /etc/passwd by
                # echoing a passwd-shaped body when the XML declares one; the safe
                # mock never does. The probe matches the root:x:0:0: signature.
                passwd = b'<r>root:x:0:0:root:/root:/bin/bash</r>'
                if mode == 'xxe-vuln' and b'SYSTEM' in raw and b'passwd' in raw:
                    self._send(200, passwd, 'application/xml')
                elif mode == 'xxe-xinclude' and b'xi:include' in raw and b'passwd' in raw:
                    # Disallow-DOCTYPE but processes XInclude: the SYSTEM/DOCTYPE
                    # payloads are rejected, the XInclude one reads the file.
                    self._send(200, passwd, 'application/xml')
                elif mode == 'xxe-xinclude' and b'DOCTYPE' in raw:
                    self._send(400, b'<error>DOCTYPE is disallowed</error>', 'application/xml')
                elif mode == 'xxe-doctype-reject' and b'DOCTYPE' in raw:
                    # Hardened: rejects every DOCTYPE, but the error page echoes a
                    # passwd-shaped diagnostic line (the false-positive trap). The
                    # inert-DOCTYPE control sees the SAME page, so it must NOT
                    # confirm -- no external entity was ever resolved.
                    self._send(400, b'<error>DOCTYPE disallowed; env root:x:0:0:root:/root:/bin/bash</error>',
                               'application/xml')
                else:
                    self._send(200, b'<r>ok</r>', 'application/xml')
                return
            if mode.startswith('massassign'):
                # Vulnerable mock binds known model fields (echoes their marker
                # values) but drops unknown ones -- including the probe's random
                # control field, so reflection stays a usable discriminator. Safe
                # mock binds nothing. (role/isAdmin/... are canonical, so echoing
                # a couple is enough for the probe to find a mass-assignable one.)
                try: o = json.loads(raw)
                except Exception: o = {}
                known = {'role', 'roles', 'is_admin', 'isAdmin', 'admin', 'is_superuser',
                         'superuser', 'user_id', 'userId', 'owner', 'balance', 'credit',
                         'price', 'status', 'plan', 'tier', 'is_active', 'active',
                         'enabled', 'verified', 'is_verified', 'permissions'}
                if mode == 'massassign-validecho':
                    # Allow-list serializer that VALIDATES known fields and ECHOES
                    # the bad value in a 4xx error, but binds NOTHING; drops
                    # unknown fields (so the junk control passes -> reflectionUsable
                    # stays true). The probe must NOT report these: reflection in a
                    # validation error is not binding, so only 2xx echoes count.
                    bad = {k: v for k, v in o.items() if k in known} if isinstance(o, dict) else {}
                    if bad:
                        echoed = ' '.join(str(v) for v in bad.values())
                        self._send(422, ('{"error":"invalid value(s): %s"}' % echoed).encode(),
                                   'application/json'); return
                    self._send(200, b'{}', 'application/json'); return
                out = {k: v for k, v in o.items()
                       if mode == 'massassign-vuln' and k in known} if isinstance(o, dict) else {}
                self._send(200, json.dumps(out).encode(), 'application/json'); return
            if mode.startswith('oast'):
                # Blind-XXE-vulnerable parser: the blast POSTs an XML body with an
                # external entity SYSTEM "<sink-url>"; a victim parser fetches it.
                if mode == 'oast-vuln':
                    mm = re.search(rb'https?://[^\s;|&)`\'">]+', raw)
                    if mm:
                        try: urllib.request.urlopen(mm.group(0).decode(), timeout=3).read()
                        except Exception: pass
                self._send(200, b'<r>ok</r>', 'application/xml'); return
            if mode.startswith('deser-body'):
                # Raw-body Java deserializer: accepts a valid serialized object
                # (the well-formed control), errors on a malformed one, and
                # "invalid stream header"s anything that isn't a Java stream. The
                # -safe variant never deserializes. Same differential as query mode.
                jwf = base64.b64decode('rO0ABXQAA2FiYw==')
                derr = b'<html>java.io.StreamCorruptedException: bad stream</html>'
                if mode == 'deser-body-vuln':
                    if raw == jwf:                       self._send(200, b'<html>ok</html>'); return
                    if raw[:4] == b'\xac\xed\x00\x05':   self._send(200, derr); return
                    self._send(200, b'<html>invalid stream header</html>'); return
                self._send(200, b'<html>ok</html>'); return    # deser-body-safe
            if mode.startswith('deser-field'):
                # A form field deserializer: the POST body is field=<base64>;
                # url-decode the value and apply the same Java differential.
                fv = parse_qs(raw.decode('utf-8', 'replace'))
                val = next((vs[0] for vs in fv.values() if vs), '')
                if mode == 'deser-field-vuln':
                    if val == 'rO0ABXQAA2FiYw==':  self._send(200, b'<html>ok</html>'); return
                    if val.startswith('rO0'):
                        self._send(200, b'<html>java.io.StreamCorruptedException: bad stream</html>'); return
                    self._send(200, b'<html>invalid stream header</html>'); return
                self._send(200, b'<html>ok</html>'); return    # deser-field-safe
            if mode == 'jwt-body-noverify':
                # A write route that REQUIRES a body (400 without it) and gates on
                # a Bearer token's presence but never verifies it -- so the probe
                # must send the body on every shot to calibrate, then the bypass
                # is found.
                if not raw: self._send(400, b'body required'); return
                auth = self.headers.get('Authorization', '')
                tok = auth[7:] if auth.lower().startswith('bearer ') else ''
                self._send(200 if tok else 401, b'ok' if tok else b'no'); return
            self._send(200, b'{"ok":true}', 'application/json')
        def do_OPTIONS(self):
            # method_audit reads the Allow header. method-allow advertises write +
            # WebDAV verbs (must be graded INFO -- advertised, not confirmed); any
            # other method-* mode advertises only benign verbs.
            if mode == 'method-allow':
                self._send(200, b'', extra=[('Allow', 'GET, HEAD, POST, OPTIONS, PUT, DELETE, PROPFIND, MKCOL')]); return
            if mode == 'method-405':
                # OPTIONS deliberately omits Allow -> the only way to learn the
                # method set is the 405 harvest (do_XYZZY below).
                self._send(200, b''); return
            if mode == 'method-track':
                # A proxy blocks OPTIONS outright -> the audit must fall through to
                # the 405 harvest and the TRACE/TRACK family instead of aborting.
                self._send(403, b'forbidden'); return
            if mode.startswith('method'):
                self._send(200, b'', extra=[('Allow', 'GET, HEAD, POST, OPTIONS')]); return
            self._send(501, b'no'); return
        def do_TRACE(self):
            # method-trace echoes the received request verbatim (true XST loopback,
            # body starts with the request line). method-trace-fp quotes the
            # request MID-body in a logging page (must NOT be flagged after the
            # offset-0 tightening). Other modes do not echo.
            if mode == 'method-trace':
                lines = 'TRACE ' + self.path + ' HTTP/1.1\r\n'
                for k, v in self.headers.items(): lines += '%s: %s\r\n' % (k, v)
                self._send(200, lines.encode(), 'message/http'); return
            if mode == 'method-trace-fp':
                lines = 'TRACE ' + self.path + ' HTTP/1.1\r\n'
                for k, v in self.headers.items(): lines += '%s: %s\r\n' % (k, v)
                self._send(200, ('<pre>logged request: ' + lines + '</pre>').encode()); return
            self._send(405, b'no'); return
        def do_TRACK(self):
            # IIS's TRACE alias. method-track echoes it back verbatim (XST via the
            # alias) even though OPTIONS is blocked -- the body starts with the
            # TRACK request line, which the audit confirms against the TRACK token.
            if mode == 'method-track':
                lines = 'TRACK ' + self.path + ' HTTP/1.1\r\n'
                for k, v in self.headers.items(): lines += '%s: %s\r\n' % (k, v)
                self._send(200, lines.encode(), 'message/http'); return
            self._send(405, b'no'); return
        def do_XYZZY(self):
            # The audit's deliberately-bogus method. method-405 answers 405 WITH an
            # Allow header (the harvest source) -- modeling servers that surface the
            # method set on 405 but not on OPTIONS. Elsewhere it's a plain 501.
            if mode == 'method-405':
                self._send(405, b'method not allowed',
                           extra=[('Allow', 'GET, HEAD, POST, OPTIONS, PUT, DELETE')]); return
            self._send(501, b'no'); return
        def do_GET(self):
            q = parse_qs(urlparse(self.path).query)
            if mode.startswith('cache'):
                # Stateful shared-cache simulation for the cache-poisoning probe.
                #   cache-keyed-vuln: keys on path+ncb (correct partitioning) and
                #     emits X-Cache HIT/MISS -> the gate confirms the buster is
                #     keyed, the injected X-Forwarded-Host is stored under the
                #     busted key and re-served to a header-less re-request ->
                #     cacheConfirmed (the true-positive critical path).
                #   cache-unkeyed: keys on path only (ignores ncb) but DOES emit
                #     hit signals -> the gate's different-buster probe still hits
                #     -> ABORT (unkeyed); no header is ever injected.
                #   cache-silent: keys on path only AND emits NO hit-signal
                #     header -> the same-buster repeat shows no signal -> the
                #     FAIL-CLOSED gate aborts (keying unprovable) instead of
                #     poisoning the real key. Regression-locks the headline bug:
                #     old code treated "no signal" as "safe to inject".
                path = urlparse(self.path).path
                ncb = (q.get('ncb') or [''])[0]
                xfh = self.headers.get('X-Forwarded-Host', '')
                silent = (mode == 'cache-silent')
                keyed = (mode == 'cache-keyed-vuln')
                store = state.setdefault('cache', {})
                key = path + ('|' + ncb if keyed else '')
                cc = [('Cache-Control', 'public, max-age=60')]
                if key in store:
                    extra = cc + ([] if silent else [('X-Cache', 'HIT'), ('Age', '7')])
                    self._send(200, store[key], 'text/html', extra); return
                body = ('<html><body>home ' + xfh + '</body></html>').encode()
                store[key] = body
                extra = cc + ([] if silent else [('X-Cache', 'MISS')])
                self._send(200, body, 'text/html', extra); return
            if mode.startswith('cd-'):
                # Web cache-deception mock. A fixed-length "account" page stands
                # in for per-user sensitive content.
                #   cd-vuln: serves the account page for ANY path under /account
                #     (the .css suffix is ignored = path confusion) and 404s any
                #     other base (incl the probe's bogus catch-all control) -> a
                #     real, cacheable (public,max-age=300) deception -> hit/high.
                #   cd-catchall: SPA history-fallback -- serves the SAME shell at
                #     EVERY path incl the bogus control -> the inert control fires
                #     -> all hits suppressed (catchAll), no false finding.
                #   cd-maxage0: like cd-vuln but Cache-Control: max-age=0 (store-
                #     but-revalidate, NOT a shareable hit) -> hit but NOT cacheable
                #     -> medium not high (locks the ccSeconds reuse).
                path = urlparse(self.path).path
                page = (b'<html><body>account dashboard: user=alice '
                        b'balance=12345 ssn=xxx-xx-6789 apikey=sk-live-abcdef0123'
                        b'</body></html>')
                if mode == 'cd-catchall':
                    self._send(200, page, 'text/html', [('Cache-Control', 'public, max-age=300')]); return
                if path.startswith('/account'):
                    ccv = 'max-age=0' if mode == 'cd-maxage0' else 'public, max-age=300'
                    self._send(200, page, 'text/html', [('Cache-Control', ccv)]); return
                self._send(404, b'<html>not found</html>'); return
            if mode.startswith('fp-'):
                # fp-prose merely MENTIONS Joomla/Drupal versions in body text
                # (no generator meta, no product path) -> must NOT be detected
                # with a version (that would CVE-correlate the scanned site);
                # fp-real has a real Joomla generator meta -> detected w/ version.
                if mode == 'fp-prose':
                    self._send(200, b'<html><body>A flaw in Joomla! 3.4.5 and Drupal 7.58 '
                                    b'was disclosed; see the advisory.</body></html>'); return
                if mode == 'fp-real':
                    self._send(200, b'<html><head><meta name="generator" content="Joomla! 3.9.28">'
                                    b'</head><body>home</body></html>'); return
                self._send(200, b'<html>ok</html>'); return
            if mode.startswith('hdr-'):
                # Security-header audit. Each mode returns a response carrying one
                # interesting header so the analyzer's headline fixes are checked
                # end-to-end (HSTS modes need TLS, so they're unit-tested only).
                #   hdr-noscript : CSP with no script-src/default-src -> script is
                #                  unrestricted -> csp-no-script-restriction (high).
                #   hdr-wildcard : script-src https://* -> csp-wildcard-source.
                #   hdr-xfo-allowall : X-Frame-Options: ALLOWALL (permissive) ->
                #                  still clickjacking-missing.
                if mode == 'hdr-noscript':
                    self._send(200, b'<html>ok</html>', 'text/html',
                               [('Content-Security-Policy', "img-src 'self'; upgrade-insecure-requests")]); return
                if mode == 'hdr-wildcard':
                    self._send(200, b'<html>ok</html>', 'text/html',
                               [('Content-Security-Policy', 'script-src https://*')]); return
                if mode == 'hdr-xfo-allowall':
                    self._send(200, b'<html>ok</html>', 'text/html',
                               [('X-Frame-Options', 'ALLOWALL')]); return
                self._send(200, b'<html>ok</html>'); return
            if mode.startswith('waf-'):
                # Passive WAF/CDN/LB detection mock.
                #   waf-detect: a site fronted by Cloudflare AND Imperva Incapsula.
                #     cf-ray (presence) + Server: cloudflare (value) both point at
                #     Cloudflare -> must dedup to ONE Cloudflare row (cf-ray wins);
                #     x-iinfo + an incap_ses cookie add Imperva Incapsula. The
                #     'session=BIGipServer...' cookie has the F5 needle in its
                #     VALUE only -> must NOT add an F5 row (cookie NAME-only match).
                #   waf-clean: plain nginx + a generic cookie -> zero detections.
                if mode == 'waf-detect':
                    self._send(200, b'<html>home</html>', 'text/html', [
                        ('cf-ray', '8abc1234def-DFW'),
                        ('Server', 'cloudflare'),
                        ('x-iinfo', '1-23456789-12345678 ABC'),
                        ('Set-Cookie', 'incap_ses_1234_5678=abc; path=/'),
                        ('Set-Cookie', 'session=BIGipServer_lookalike_value; path=/'),
                    ]); return
                self._send(200, b'<html>home</html>', 'text/html', [
                    ('Server', 'nginx'), ('Set-Cookie', 'sid=plain; path=/')]); return
            if mode.startswith('secrets'):
                # secrets-vuln embeds a high-entropy assigned secret (a generic
                # shape, NOT a provider key, to avoid any real-key concern);
                # secrets-example embeds a placeholder value that must be
                # filtered now that looksPlaceholder applies to every match.
                if mode == 'secrets-vuln':
                    self._send(200, b'<html><script>var apikey="aB3xK9mQ2pL7vR4nT8wZ";</script></html>'); return
                if mode == 'secrets-example':
                    self._send(200, b'<html><script>var apikey="your_api_key_example_here";</script></html>'); return
                self._send(200, b'<html>ok</html>'); return
            if mode.startswith('exposure'):
                path = urlparse(self.path).path
                if mode == 'exposure-vuln':
                    # only /.git/config exists (real git config text); all else 404
                    if path.endswith('/.git/config'):
                        self._send(200, b'[core]\n\trepositoryformatversion = 0\n\tbare = false\n'); return
                    self._send(404, b'not found'); return
                if mode == 'exposure-env':
                    # real .env (text/plain, >=2 UPPERCASE= lines)
                    if path.endswith('/.env'):
                        self._send(200, b'DB_PASSWORD=hunter2\nAPI_KEY=abcdef\nDEBUG=true\n'); return
                    self._send(404, b'not found'); return
                if mode == 'exposure-catchall':
                    # 200 SPA shell at EVERY path incl /.env and the bogus control
                    # -> rejectHtml + soft-404 calibration must suppress every hit.
                    self._send(200, b'<!doctype html><html><head><script>var APP_VERSION=1;'
                                    b'MODE_PROD=2;</script></head><body>app</body></html>'); return
                self._send(404, b'not found'); return
            if mode.startswith('paramminer'):
                qd = parse_qs(urlparse(self.path).query)
                if mode == 'paramminer-reflect':
                    # Only the real param 'q' is echoed; the junk control name is
                    # not, so reflectionSignalUsable stays true.
                    v = (qd.get('q') or [''])[0]
                    self._send(200, ('<html>results for ' + v + '</html>').encode()); return
                if mode == 'paramminer-status':
                    # 'admin' flips status to 500 deterministically (re-confirm
                    # reproduces); everything else stays 200.
                    self._send(500 if 'admin' in qd else 200, b'<html>ok</html>'); return
                if mode == 'paramminer-echoall':
                    # Reflects EVERY param value incl the junk control -> the
                    # junk-control must disable the reflection signal (FP guard).
                    vals = ' '.join(x for vs in qd.values() for x in vs)
                    self._send(200, ('<html>' + vals + '</html>').encode()); return
                self._send(200, b'<html>ok</html>'); return
            if mode.startswith('takeover'):
                # takeover-vuln serves a BRANDED dangling-service page (a real
                # candidate); takeover-apache404 serves the stock Apache 404 body
                # -- which must NOT flag now that the generic "Unbounce" = Apache
                # fingerprint is pruned (the headline false-positive fix).
                if mode == 'takeover-vuln':
                    self._send(404, b'<html>Fastly error: unknown domain: x.example.com</html>'); return
                if mode == 'takeover-apache404':
                    self._send(404, b'<html><head><title>404 Not Found</title></head><body>'
                                    b'<h1>Not Found</h1><p>The requested URL was not found on '
                                    b'this server.</p></body></html>'); return
                self._send(200, b'<html>ok</html>'); return
            if mode.startswith('sspp'):
                obj = {'user': 'alice', 'role': 'admin', 'id': 1}
                if mode == 'sspp-gzip':
                    self._send(200, gzip.compress(json.dumps(obj).encode()), 'application/json',
                               [('Content-Encoding', 'gzip')]); return
                body = (json.dumps(obj, indent=state['spaces']) if state['spaces'] > 0
                        else json.dumps(obj, separators=(',', ':'))).encode()
                self._send(200, body, 'application/json'); return
            if mode.startswith('hh'):
                xfh = self.headers.get('X-Forwarded-Host', '')
                if mode == 'hh-host-loc':
                    # Echo the literal Host LINE into a redirect -> the HIGH tier
                    # (the Host-replacement probe sends Host:<sentinel>).
                    host = self.headers.get('Host', '')
                    self._send(302, b'', 'text/html', [('Location', 'https://%s/welcome' % host)]); return
                if mode == 'hh-location':
                    # Forwarding header echoed into a redirect -> MEDIUM tier.
                    self._send(302, b'', 'text/html', [('Location', 'https://%s/welcome' % xfh)]); return
                if mode == 'hh-cookie':
                    self._send(200, b'<html>ok</html>', 'text/html',
                               [('Set-Cookie', 'sid=1; Domain=%s; Path=/' % xfh)]); return
                if mode == 'hh-urlbody':   b = ('<a href="https://%s/reset?token=abc">r</a>' % xfh).encode()
                elif mode == 'hh-urlattr': b = ('<a href=//%s/reset>r</a>' % xfh).encode()  # UNQUOTED proto-rel
                elif mode == 'hh-bare':    b = ('<p>requested host = %s</p>' % xfh).encode()
                elif mode == 'hh-comment': b = ('<!-- proxied via //%s internal -->' % xfh).encode()
                else:                      b = b'<a href="https://canonical.example/r">x</a>'
                self._send(200, b, 'text/html'); return
            if mode.startswith('ldap'):
                err = b'<html>javax.naming.directory.InvalidSearchFilterException: invalid search filter</html>'
                ok  = b'<html>0 results</html>'
                val = q.get('q', [''])[0]
                if mode == 'ldap-baseline': self._send(200, err); return
                if mode == 'ldap-vuln':     self._send(200, err if ('(' in val or ')' in val) else ok); return
                if mode == 'ldap-waf':
                    # WAF blocks LDAP metacharacters with a 403 page that mentions
                    # a GENERIC LDAP error string -- the generic-family block-status
                    # guard must reject it (no real backend filter break).
                    if ('(' in val or ')' in val or '*' in val):
                        self._send(403, b'<html>Request blocked: possible LDAP: error code injection</html>'); return
                    self._send(200, ok); return
                self._send(200, ok); return
            if mode.startswith('xpath'):
                err = b'<html>javax.xml.xpath.XPathExpressionException: invalid XPath expression</html>'
                ok  = b'<html>0 nodes</html>'
                val = q.get('q', [''])[0]
                brk = any(c in val for c in "'\"])")
                if mode == 'xpath-waf':
                    # WAF blocks XPath metacharacters with a 403 page naming the
                    # attack class -- the generic-family block-status guard must
                    # reject it (no real backend expression break).
                    if brk:
                        self._send(403, b'<html>Error: XPath injection blocked by WAF</html>'); return
                    self._send(200, ok); return
                self._send(200, err if (mode == 'xpath-vuln' and brk) else ok); return
            if mode.startswith('h3'):
                alt = {'h3-adv': 'h3=":443"; ma=86400, h3-29=":443", h2=":443"',
                       'h3-h2only': 'h2=":443"; ma=3600',
                       'h3-clear': 'clear'}.get(mode)
                extra = [('Alt-Svc', alt)] if alt is not None else []
                self._send(200, b'ok\n', 'text/plain', extra); return
            if mode.startswith('ssrf'):
                # Each mode simulates one server behaviour the probe must judge.
                # The probe confirms only on fetch-only signatures (never in the
                # URL it sent) that are absent from the baseline AND absent from
                # a same-shape non-fetchable "shaped control" URL (tag below).
                val = q.get('url', [''])[0]
                ctl = 'nullock-ssrf-zq9x1k7p'   # shaped-control marker -> non-fetchable
                body = b'<html>home</html>'
                if mode == 'ssrf-vuln':
                    # Fully vulnerable cloud host: IMDS v1 listing, the IAM
                    # two-step (role listing then credential doc), and file read.
                    if '/iam/security-credentials/' in val and ctl not in val:
                        if val.rstrip('/').endswith('/iam/security-credentials'):
                            body = b'nullock-role\n'                       # role listing
                        elif val.endswith('/iam/security-credentials/nullock-role'):
                            body = b'{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"redacted-fake"}'
                    elif '169.254.169.254/latest/meta-data/' in val and ctl not in val:
                        body = b'ami-id\ninstance-id\nplacement/\n'
                    elif val.startswith('file:///etc/passwd'):
                        body = b'root:x:0:0:root:/root:/bin/bash\n'
                elif mode == 'ssrf-fp':
                    # An error/WAF template that echoes a passwd EXAMPLE for ANY
                    # file:// value (real path or the shaped control). The shaped
                    # control must catch this and suppress the hit (no fetch).
                    if val.startswith('file://'):
                        body = b'root:x:0:0:example-shown-by-error-page\n'
                elif mode == 'ssrf-bypass':
                    # Denylist blocks the literal 169.254.169.254, but the
                    # decimal-encoded host still reaches IMDS.
                    if '2852039166/latest/meta-data/' in val and ctl not in val:
                        body = b'ami-id\ninstance-id\n'
                elif mode == 'ssrf-internal':
                    # The fetcher reaches an internal Elasticsearch on loopback.
                    if '127.0.0.1:9200' in val and ctl not in val:
                        body = b'{"name":"node-1","cluster_name":"nullock-es"}'
                # ssrf-safe falls through to the static home page.
                self._send(200, body); return
            if mode.startswith('deser-cookie'):
                # A Java-deserializing rememberMe cookie: accepts the valid
                # serialized object (well-formed control), errors on a malformed
                # one. Same differential, carried in the Cookie header.
                ck = self.headers.get('Cookie', '')
                cval = ck.split('=', 1)[1] if '=' in ck else ''
                if mode == 'deser-cookie-vuln':
                    if cval == 'rO0ABXQAA2FiYw==':  self._send(200, b'<html>ok</html>'); return
                    if cval.startswith('rO0'):
                        self._send(200, b'<html>java.io.StreamCorruptedException: bad stream</html>'); return
                    self._send(200, b'<html>invalid stream header</html>'); return
                self._send(200, b'<html>ok</html>'); return    # deser-cookie-safe
            if mode.startswith('deser'):
                # Confirmation is well-formed-vs-malformed: a real deserializer
                # ACCEPTS a valid serialized object and ERRORS on a malformed one.
                #   deser-<fmt>-vuln : a real deserializer for that format -- accepts
                #                      ITS valid blob, errors on everything else
                #   deser-safe       : echo/store -> never errors
                #   deser-shapewaf   : a blocklist that errors on ANY serialized
                #                      magic (incl. well-formed) -> must NOT flag
                #   deser-baseline   : errors on everything -> must NOT flag
                val = q.get('data', [''])[0]
                # serialized-magic prefixes a real shape-WAF keys on: Java rO0,
                # any pickle (\x80 -> gA), Ruby Marshal BAh, PHP object/array,
                # .NET BinaryFormatter. Catches BOTH the well-formed and malformed
                # control of each format (else the WAF case would not be modeled).
                magic = (val.startswith('rO0') or val.startswith('gA')
                         or val.startswith('BAh') or val.startswith('O:')
                         or val.startswith('a:') or val.startswith('AAEAAAD'))
                jerr = b'<html>java.io.StreamCorruptedException: bad stream</html>'
                ok   = b'<html>ok</html>'
                # one real deserializer per format: (well-formed blob it accepts,
                # the engine-specific parse error it emits for anything else)
                sinks = {
                    'deser-vuln':        ('rO0ABXQAA2FiYw==',                 jerr),
                    'deser-php-vuln':    ('O:8:"stdClass":1:{s:1:"a";i:1;}',
                                          b'<html>unserialize(): Error at offset 0 of 11 bytes</html>'),
                    'deser-python-vuln': ('gAJLAS4=',
                                          b'<html>_pickle.UnpicklingError: pickle data was truncated</html>'),
                    'deser-ruby-vuln':   ('BAhpBg==',
                                          b'<html>ArgumentError: marshal data too short</html>'),
                }
                if mode == 'deser-baseline':
                    self._send(200, jerr); return                     # always errors
                if mode == 'deser-shapewaf':
                    self._send(200, jerr if magic else ok); return    # blocks all magic, incl. well-formed
                if mode in sinks:
                    wf, ferr = sinks[mode]
                    self._send(200, ok if val == wf else ferr); return  # accept own valid blob, else error
                self._send(200, ok); return                           # deser-safe
            if mode.startswith('oastlog4'):
                # A Log4Shell-vulnerable server: a ${jndi:ldap://<token>.<host>:
                # <port>/a} in a logged header triggers a JNDI lookup whose DNS
                # resolution lands the token on our DNS sink. -safe logs inertly.
                if mode == 'oastlog4-vuln':
                    for hv in self.headers.values():
                        m = re.search(r'\$\{jndi:ldap://([^/}]+)', hv)
                        if m:
                            hp = m.group(1)                      # <token>.<host>:<port>
                            host = hp.split(':')[0]
                            port = int(hp.split(':')[1]) if ':' in hp else 53
                            server = host.split('.', 1)[1] if '.' in host else host
                            fire_dns(host, server, port)
                self._send(200, b'ok'); return
            if mode.startswith('oast'):
                # A server vulnerable to the OAST blast's GET vectors: it acts on
                # an attacker-controlled URL in a param -- whether the value is a
                # bare URL (SSRF param) or a shell command fetching one (RCE
                # ;curl/$(curl)/`curl`). Either way a real victim makes the
                # out-of-band request, so the mock fires the callback to our sink.
                # The -safe variant ignores it.
                if mode == 'oast-vuln':
                    for vals in q.values():
                        for v in vals:
                            mm = re.search(r'https?://[^\s;|&)`\'"]+', v)
                            if mm:
                                try: urllib.request.urlopen(mm.group(0), timeout=3).read()
                                except Exception: pass
                self._send(200, b'<html>ok</html>'); return
            if mode.startswith('jwt'):
                # An auth-gated endpoint behind a JWT. All modes 401 a missing
                # token (so the probe can calibrate "gated"). They differ in how
                # they (mis)handle the signature:
                #   jwt-safe     : verifies HS256 (strong secret), pins the alg
                #   jwt-algnone  : verifies HS256 but ALSO accepts alg:none (bug)
                #   jwt-noverify : gates on token PRESENCE, never verifies (bug)
                #   jwt-weak     : verifies HS256 with a guessable secret (bug)
                if mode == 'jwt-cookie-noverify':
                    # Reads the JWT from a cookie (not Bearer) and never verifies
                    # it -- so carrier fan-out must find the bypass via cookie:jwt
                    # even though no location was specified.
                    ck = self.headers.get('Cookie', '')
                    m = re.search(r'(?:^|;\s*)jwt=([^;]+)', ck)
                    self._send(200 if m else 401, b'ok' if m else b'unauthorized'); return
                auth = self.headers.get('Authorization', '')
                tok = auth[7:] if auth.lower().startswith('bearer ') else ''
                if not tok:
                    self._send(401, b'unauthorized'); return
                if mode == 'jwt-noverify':
                    self._send(200, b'ok'); return
                if mode in ('jwt-algconfusion', 'jwt-rs-safe'):
                    # An RS256 endpoint. Both accept the valid (placeholder-sig)
                    # RS token and 401 a corrupted one; only -algconfusion has the
                    # bug of HMAC-verifying an HS256 token with the public key.
                    parts = tok.split('.')
                    try: a = json.loads(_b64u_dec(parts[0]).decode('utf-8', 'replace')).get('alg', '')
                    except Exception: a = ''
                    if a[:2] in ('RS', 'ES', 'PS'):
                        ok_ = len(parts) >= 3 and parts[2] == JWT_FAKE_RSSIG
                        self._send(200 if ok_ else 401, b'ok' if ok_ else b'no'); return
                    if a == 'HS256' and mode == 'jwt-algconfusion':
                        v, _ = jwt_check(tok, JWT_FAKE_PUBKEY)
                        self._send(200 if v else 401, b'ok' if v else b'no'); return
                    self._send(401, b'no'); return
                secret = 'secret' if mode == 'jwt-weak' else JWT_STRONG
                valid, alg = jwt_check(tok, secret)
                if mode == 'jwt-algnone' and alg == 'none':
                    self._send(200, b'ok'); return
                self._send(200 if valid else 401, b'ok' if valid else b'unauthorized'); return
            if mode.startswith('cswsh'):
                # WebSocket upgrade endpoint. Compute the RFC-6455 accept token so
                # the probe sees a genuine handshake. The modes model the grading
                # ladder end-to-end:
                #   cswsh-vuln      : an AUTHENTICATED socket that does NOT validate
                #     Origin but DOES require the session cookie -- a cross-origin
                #     upgrade carrying the cookie completes (CSWSH) while the
                #     probe's no-cookie baseline is refused, so the socket is proven
                #     to honor the session -> CONFIRMED high.
                #   cswsh-open      : a PUBLIC socket -- accepts any Origin with or
                #     without a cookie. No credential -> Origin-not-validated LEAD;
                #     even WITH a cookie the no-cookie baseline also 101s, so the
                #     authed-baseline confirm DOWNGRADES it to the lead (never a
                #     confirmed hijack on a socket that ignores the session).
                #   cswsh-subdomain : a naive endsWith(host) allow-list -- refuses
                #     the .test sentinel and null but ACCEPTS any Origin whose host
                #     ends with the target host, so the attacker.<host> subdomain
                #     variant slips through (the false negative the variant sweep
                #     must catch -- without it the probe would call this validated).
                #   cswsh-safe      : validates Origin -- refuses every foreign
                #     Origin (incl. all derived variants) and completes only the
                #     no-Origin control.
                up = self.headers.get('Upgrade', '')
                key = self.headers.get('Sec-WebSocket-Key', '')
                origin = self.headers.get('Origin', '')
                cookie = self.headers.get('Cookie', '')
                if up.lower() != 'websocket' or not key:
                    self._send(200, b'<html>not a websocket</html>'); return
                def ohost(o):
                    h = o.split('://', 1)[1] if '://' in o else o
                    return h.split('/', 1)[0].rstrip('.').lower()
                target = '127.0.0.1'
                if mode == 'cswsh-safe':
                    if origin:                                  # any Origin -> refused
                        self._send(403, b'cross-origin handshake refused'); return
                elif mode == 'cswsh-subdomain':
                    if origin and not ohost(origin).endswith(target):   # endsWith() bug
                        self._send(403, b'cross-origin handshake refused'); return
                elif mode == 'cswsh-vuln':
                    if 'session=' not in cookie:                # authenticated socket
                        self._send(401, b'authentication required'); return
                # cswsh-open: accept any Origin regardless of cookie (fall through).
                accept = base64.b64encode(
                    hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
                self.send_response(101)
                self.send_header('Upgrade', 'websocket')
                self.send_header('Connection', 'Upgrade')
                self.send_header('Sec-WebSocket-Accept', accept)
                self.end_headers()
                return
            if mode.startswith('content'):
                # 404 everything (incl. the random calibration paths) except a
                # single real path, so discovery surfaces exactly /admin.
                p = urlparse(self.path).path.rstrip('/')
                if p == '/admin': self._send(200, b'<html>Admin Panel login</html>')
                else:             self._send(404, b'<html>404 not found</html>')
                return
            if mode.startswith('sqli'):
                val = q.get('q', [''])[0]
                if mode == 'sqli-blind':
                    # Blind-only sink: leaks NO SQL error, but an injected
                    # SLEEP(N>0) actually stalls the response by N seconds (a
                    # SLEEP(0) control stays fast) -- so only the time-based phase
                    # can confirm it. Parse N from each DBMS sleep primitive.
                    m = (re.search(r'(?:SLEEP|pg_sleep)\((\d+)\)', val)
                         or re.search(r"WAITFOR DELAY '0:0:(\d+)'", val)
                         or re.search(r"receive_message\('a',(\d+)\)", val))
                    secs = int(m.group(1)) if m else 0
                    if secs > 0:
                        time.sleep(min(secs, 6))
                    self._send(200, b'<html>results</html>'); return
                if mode == 'sqli-waf':
                    # WAF blocks odd-quote inputs with a 403 page naming the attack
                    # class (a GENERIC "SQL syntax error" string) -- the generic-
                    # family block-status guard must reject it (no real backend
                    # error; the even-quote balanced control is let through).
                    if val.count("'") % 2 == 1:
                        self._send(403, b'<html>Request blocked: SQL syntax error detected in input</html>'); return
                    self._send(200, b'<html>0 results</html>'); return
                # Error-based: an unbalanced quote (odd count) breaks the query;
                # the breaker has 1 quote (odd), the balanced control has 2 (even).
                vuln = (mode == 'sqli-vuln' and val.count("'") % 2 == 1)
                if vuln:
                    self._send(200, b'<html>You have an error in your SQL syntax; check the '
                                    b'manual that corresponds to your MySQL server version</html>')
                else:
                    self._send(200, b'<html>0 results</html>')
                return
            if mode.startswith('xss'):
                # Reflected: echo the param into element content. Vulnerable mock
                # reflects it raw (the <marker> stays an executable tag); the safe
                # mock HTML-escapes it.
                val = q.get('q', [''])[0]
                if mode == 'xss-attr':
                    # Reflect the marker RAW but into a later attribute, after an
                    # earlier quoted attribute value that contains a literal '>'.
                    # The marker lands inside the open tag (inert) -> must NOT be
                    # flagged: regression-locks the headline attribute-quote FP.
                    self._send(200, ('<input data-x="a>b" value=%s>' % val).encode()); return
                if mode == 'xss-nosniff':
                    # Reflect the marker RAW in element content, but send NO
                    # Content-Type plus X-Content-Type-Options: nosniff, so a
                    # browser won't sniff it as HTML -> not executable -> must NOT
                    # be flagged.
                    body = ('<html><body>Results for: %s</body></html>' % val).encode()
                    self.send_response(200)
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.send_header('Content-Length', str(len(body))); self.end_headers()
                    self.wfile.write(body); return
                if mode != 'xss-vuln':
                    val = val.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                self._send(200, ('<html><body>Results for: %s</body></html>' % val).encode())
                return
            if mode.startswith('crlf'):
                # HTTP response splitting. The vulnerable server reflects the
                # (decoded) first query-param value into a response header value
                # via RAW bytes -- so an injected CR/LF physically splits off a
                # new header line. We model three decoders:
                #   crlf-vuln     : decodes %0d%0a AND %3a -> a real
                #                   "X-Nullock-Crlf: <marker>" header (parsed-hit).
                #   crlf-colonless: decodes the CR/LF but NOT %3a -> a colon-less
                #                   "X-Nullock-Crlf%3a<marker>" line the parser
                #                   drops -> confirmed only via the raw fallback.
                #   crlf-safe     : strips CR/LF -> no split, not vulnerable.
                from urllib.parse import unquote
                raw = urlparse(self.path).query.split('&', 1)[0]
                rawval = raw.split('=', 1)[1] if '=' in raw else ''
                if mode == 'crlf-colonless':
                    refl = (rawval.replace('%0d', '\r').replace('%0a', '\n')
                                  .replace('%0D', '\r').replace('%0A', '\n'))
                else:
                    refl = unquote(rawval)
                    if mode == 'crlf-safe':
                        refl = refl.replace('\r', '').replace('\n', '')
                body = b'<html>ok</html>'
                resp = ('HTTP/1.0 200 OK\r\nX-Reflect: ' + refl + '\r\n'
                        + 'Content-Type: text/html\r\nContent-Length: '
                        + str(len(body)) + '\r\nConnection: close\r\n\r\n').encode() + body
                self.wfile.write(resp); return
            if mode.startswith('openredir'):
                # Vulnerable mock reflects the redirect param into a redirect
                # sink; the probe flags it resolving to its sentinel.
                val = q.get('url', [''])[0]
                clean = ('\n' not in val and '\r' not in val)
                if mode == 'openredir-vuln' and clean:
                    # Location header (3xx).
                    self.send_response(302); self.send_header('Location', val)
                    self.send_header('Content-Length', '0'); self.end_headers()
                elif mode == 'openredir-refresh' and clean:
                    # Refresh RESPONSE header -- browsers honor it like Location.
                    self.send_response(200); self.send_header('Refresh', '0;url=' + val)
                    self.send_header('Content-Length', '0'); self.end_headers()
                elif mode == 'openredir-js' and clean:
                    # Client-side JS navigation via location.assign(...).
                    body = ('<html><script>location.assign("%s")</script></html>' % val).encode()
                    self._send(200, body)
                elif mode == 'openredir-echo' and clean:
                    # SAFE: merely ECHOES the rejected payload as inert prose --
                    # the naive-reflection false positive the probe must avoid.
                    body = ('<html><body><p>Invalid location=%s</p></body></html>' % val).encode()
                    self._send(200, body)
                else:
                    self._send(200, b'<html>home</html>')
                return
            if mode.startswith('pathtrav'):
                # Vulnerable mock = a REAL file read: returns the passwd body ONLY
                # when the resolved path actually names etc/passwd, so the shaped
                # control (a bogus nonexistent name) stays clean and the hit
                # confirms. The 'template' mock = a value-keyed docs/error page
                # that emits a passwd EXAMPLE line for ANY odd value (incl. the
                # bogus control) -> the shaped control must suppress it.
                val = q.get('file', [''])[0]
                passwd = (b'root:x:0:0:root:/root:/bin/bash\n'
                          b'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n')
                if mode == 'pathtrav-vuln' and 'passwd' in val:
                    self._send(200, passwd, 'text/plain'); return
                if mode == 'pathtrav-template' and ('..' in val or 'passwd' in val):
                    # Renders an example passwd line for any traversal-shaped value
                    # (a help/error template), NOT a real read.
                    self._send(200, b'<html><pre>Example /etc/passwd entry: '
                                    + passwd + b'</pre></html>'); return
                else:
                    self._send(200, b'<html>file not found</html>')
                return
            if mode.startswith('cors'):
                # Vulnerable mock reflects the request Origin into ACAO (with
                # credentials); the probe flags reflecting its attacker origin.
                o = self.headers.get('Origin', '')
                extra = ([('Access-Control-Allow-Origin', o),
                          ('Access-Control-Allow-Credentials', 'true')]
                         if (mode == 'cors-vuln' and o) else [])
                self._send(200, b'{"ok":1}', 'application/json', extra); return
            if mode.startswith('verb'):
                # Vulnerable mock denies GET (403) but allows POST (the do_POST
                # 200 below) -- a verb-tampering bypass; an undefined method gets
                # the stdlib 501, the non-2xx control the probe needs. Safe mock
                # allows GET (200) so the probe sees nothing to bypass.
                # verb-case denies BOTH GET and POST (403), but the lower-cased
                # "get" (do_get below) flips to 200 -- a case-variation bypass.
                self._send(403 if mode in ('verb-vuln', 'verb-case') else 200,
                           b'<html>x</html>'); return
            if mode.startswith('ssti'):
                # Reflect the param; the vulnerable mock additionally EVALUATES a
                # Jinja-style {{N*N}} (one of the probe's delimiter families) to
                # the product, so the text between the probe's sentinels equals
                # a*b -- its confirmation signal. Safe mock reflects raw.
                val = q.get('q', [''])[0]
                if mode == 'ssti-vuln':
                    val = re.sub(r'\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}',
                                 lambda m: str(int(m.group(1)) * int(m.group(2))), val)
                elif mode == 'ssti-calc':
                    # A calculator / inline-math endpoint (NOT a template engine):
                    # substitutes the FIRST N*N it finds with the product. The old
                    # single-expression probe false-positived here at CRITICAL; the
                    # two-expression confirmation must NOT -- a calculator cannot
                    # evaluate two delimited sub-expressions and keep the literal
                    # separator between them.
                    val = re.sub(r'(\d+)\*(\d+)',
                                 lambda m: str(int(m.group(1)) * int(m.group(2))), val, count=1)
                self._send(200, ('<html>' + val + '</html>').encode()); return
            if mode.startswith('cmdi'):
                # The vulnerable mock simulates a real shell: it performs BOTH
                # arithmetic expansion $((N*N)) AND command substitution
                # $(echo ...), so the injected $(echo $((a*b))) collapses to the
                # product between the sentinels. The 'arith' mock is a RESTRICTED
                # evaluator that only expands $((N*N)) and does NOT run $() -- it
                # must NOT be confirmed (the audit's arithmetic-only false
                # positive, now defeated by requiring command substitution).
                val = q.get('cmd', [''])[0]
                if mode in ('cmdi-vuln', 'cmdi-arith'):
                    val = re.sub(r'\$\(\((\d+)\*(\d+)\)\)',
                                 lambda m: str(int(m.group(1)) * int(m.group(2))), val)
                if mode == 'cmdi-vuln':
                    prev = None
                    while prev != val:   # resolve nested $(echo ...) substitutions
                        prev = val
                        val = re.sub(r'\$\(\s*echo\s+([^()]*?)\s*\)',
                                     lambda m: m.group(1), val)
                self._send(200, ('<html>' + val + '</html>').encode()); return
            if mode.startswith('nosqli'):
                # A real Mongo backend over-matches on BOTH always-true operators
                # ($ne and $gt) -> LONG body, while the literal and the always-
                # false $eq match nothing -> short body. The vuln mock simulates
                # that. The 'namedeny' mock keys ONLY on the $ne NAME (a validator
                # returning a verbose page) -- $gt is untouched, so the 2x2
                # differential must REJECT it. Safe mock ignores operators.
                keys = list(q.keys())
                has_true = any(k.endswith('[$ne]') or k.endswith('[$gt]') for k in keys)
                has_ne = any(k.endswith('[$ne]') for k in keys)
                long_body = b'<html>' + b'<li>record</li>\n' * 60 + b'</html>'
                short_body = b'<html>1 result</html>'
                if mode == 'nosqli-vuln' and has_true:
                    self._send(200, long_body)
                elif mode == 'nosqli-namedeny' and has_ne:
                    self._send(200, long_body)   # only $ne diverges; $gt does not
                else:
                    self._send(200, short_body)
                return
            if mode.startswith('idor'):
                # Vulnerable mock serves a distinct object per id (so a neighbor
                # id returns a real OTHER object: 200, body != yours, length !=
                # the not-found control) -- BOLA. Out-of-range control ids 404.
                # Safe mock ignores the id (same body for all -> not "someone
                # else's object").
                raw = q.get('id', [''])[0]
                try: n = int(raw)
                except Exception: n = -1
                if mode == 'idor-ctrlfail':
                    # Distinct object per id, BUT the wildly-out-of-range
                    # discriminator id (>1000000) drops the connection so the
                    # control SEND fails -> the fail-closed gate must skip the
                    # location (no finding), instead of flagging every 2xx.
                    if n > 1000000:
                        try: self.connection.close()
                        except Exception: pass
                        return
                    if 0 <= n <= 1000000:
                        self._send(200, ('<html>Account %d: owner user_%d</html>' % (n, n)).encode())
                    else:
                        self._send(404, b'<html>not found</html>')
                    return
                if mode == 'idor-padded':
                    # Width-strict id space: only zero-padded width-5 ids resolve
                    # (/?id=00042). Unpadded neighbors ("43") 404, so ONLY a
                    # padding-preserving probe enumerates the neighbors.
                    if re.match(r'^0\d{4}$', raw):
                        self._send(200, ('<html>Doc %d: confidential record, owner user_%d, '
                                         'balance $%d, email user%d@corp.test</html>'
                                         % (n, n, n * 7, n)).encode())
                    else:
                        self._send(404, b'<html>not found</html>')
                    return
                if mode == 'idor-vuln' and 0 <= n <= 1000000:
                    self._send(200, ('<html>Account %d: balance $%d, owner user_%d, '
                                     'email user%d@corp.test</html>' % (n, n * 7, n, n)).encode())
                elif mode == 'idor-vuln':
                    self._send(404, b'<html>not found</html>')
                else:
                    self._send(200, b'<html>your dashboard</html>')
                return
            self._send(200, b'ok\n', 'text/plain')
        def do_get(self):   # lower-cased GET -- the verb-case bypass vector
            if mode == 'verb-case':
                self._send(200, ('<html>confidential report: revenue $5.2M, headcount '
                                 '312, runway 18mo, board notes attached</html>').encode())
            else:
                self._send(404, b'<html>not found</html>')
        def log_message(self, *a): pass
    return H
socketserver.TCPServer.allow_reuse_address = True
# Bind each mode to an OS-assigned ephemeral port and report the actual port,
# so we never collide with a busy or Windows-reserved port (WinError 10013).
for mode in sys.argv[1:]:
    srv = socketserver.TCPServer(('127.0.0.1', 0), make(mode))
    print("PORT %s %d" % (mode, srv.server_address[1]), flush=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
print("READY", flush=True)
while True: time.sleep(1)
PY

# Start the mocks on OS-assigned ports; read the actual port map back from the
# mock's stdout (avoids any reserved/busy-port collision).
MODES=(sspp-vuln sspp-safe sspp-gzip sspp-ctor
       hh-urlbody hh-location hh-bare hh-safe hh-comment hh-cookie hh-host-loc hh-urlattr
       sqli-vuln sqli-safe sqli-blind sqli-waf
       xss-vuln xss-safe xss-attr xss-nosniff
       crlf-vuln crlf-colonless crlf-safe
       method-allow method-trace method-trace-fp method-405 method-track
       openredir-vuln openredir-safe openredir-refresh openredir-js openredir-echo
       pathtrav-vuln pathtrav-safe pathtrav-template
       cors-vuln cors-safe
       verb-vuln verb-safe verb-case
       ssti-vuln ssti-safe ssti-calc
       cmdi-vuln cmdi-safe cmdi-arith
       nosqli-vuln nosqli-safe nosqli-namedeny
       idor-vuln idor-safe idor-ctrlfail idor-padded
       xxe-vuln xxe-safe xxe-xinclude xxe-doctype-reject
       ssrf-vuln ssrf-safe ssrf-fp ssrf-bypass ssrf-internal
       deser-vuln deser-php-vuln deser-python-vuln deser-ruby-vuln
       deser-safe deser-shapewaf deser-baseline
       deser-body-vuln deser-body-safe
       deser-cookie-vuln deser-cookie-safe
       deser-field-vuln deser-field-safe
       massassign-vuln massassign-safe massassign-validecho
       ldap-vuln ldap-safe ldap-baseline ldap-waf
       xpath-vuln xpath-safe xpath-waf
       content-found
       cswsh-vuln cswsh-open cswsh-safe cswsh-subdomain
       jwt-safe jwt-algnone jwt-noverify jwt-weak jwt-algconfusion jwt-rs-safe jwt-cookie-noverify
       jwt-body-noverify
       oast-vuln oast-safe oastlog4-vuln oastlog4-safe
       cache-keyed-vuln cache-unkeyed cache-silent
       cd-vuln cd-catchall cd-maxage0
       takeover-vuln takeover-apache404
       race-vuln race-atomic race-overgrant race-noise
       paramminer-reflect paramminer-status paramminer-echoall
       exposure-vuln exposure-env exposure-catchall
       secrets-vuln secrets-example
       fp-prose fp-real
       waf-detect waf-clean
       hdr-noscript hdr-wildcard hdr-xfo-allowall
       h3-adv h3-h2only h3-none h3-clear)
MOCK_OUT="$(mktemp /tmp/nullock-probe-mock-out.XXXXXX)"
python "$MOCK" "${MODES[@]}" > "$MOCK_OUT" 2>&1 & MOCK_PID=$!
for _ in $(seq 1 60); do grep -q '^READY' "$MOCK_OUT" 2>/dev/null && break; sleep 0.25; done
declare -A P
while read -r tag mode pport; do
  pport="${pport%$'\r'}"; mode="${mode%$'\r'}"   # Windows python prints CRLF
  [ "$tag" = "PORT" ] && [ -n "$pport" ] && P["$mode"]="$pport"
done < "$MOCK_OUT"
if [ "${#P[@]}" -ne "${#MODES[@]}" ]; then
  echo "FATAL: mocks did not all start (got ${#P[@]}/${#MODES[@]})"; sed -n '1,20p' "$MOCK_OUT"
  kill "$MOCK_PID" 2>/dev/null; rm -f "$MOCK" "$MOCK_OUT"; exit 2
fi

CTL=$(( (RANDOM % 4000) + 21000 ))
PROJ="$(mktemp -d /tmp/nullock-probe-proj.XXXXXX)"
"$EXE" --headless --control-port="$CTL" --proxy-port="$(( CTL + 1 ))" --project="$PROJ" --no-update-check &
APP_PID=$!
cleanup() { kill "$MOCK_PID" "$APP_PID" 2>/dev/null; rm -f "$MOCK" "$MOCK_OUT"; rm -rf "$PROJ"; }
trap cleanup EXIT

BASEURL="http://127.0.0.1:$CTL"
HDR=(-H "Content-Type: application/json" -H "Origin: $BASEURL" -H "X-Nullock-UI: 1")
for _ in $(seq 1 40); do curl -sS --max-time 2 "$BASEURL/api/snapshot" >/dev/null 2>&1 && break; sleep 0.5; done
sleep 1
# Fail fast + clearly if the control server never came up on the expected port
# (e.g. the requested port was busy and the app fell back to another), rather
# than emitting a wall of confusing per-probe connection failures.
if ! curl -sS --max-time 3 "$BASEURL/api/snapshot" >/dev/null 2>&1; then
  echo "FATAL: control server not reachable on $CTL (port busy / app failed to start)"
  exit 2
fi

PASS=0; FAIL=0
# chk <label> <json> <python-bool-expr over `d`>
chk() {
  local label="$1" body="$2" expr="$3"
  if printf '%s' "$body" | python -c "import json,sys
d=json.load(sys.stdin)
sys.exit(0 if ($expr) else 1)" 2>/dev/null; then
    echo "  PASS  $label"; PASS=$(( PASS + 1 ))
  else
    echo "  FAIL  $label  ::  $body"; FAIL=$(( FAIL + 1 ))
  fi
}
post() { curl -sS --max-time 30 "${HDR[@]}" -X POST -d "$2" "$BASEURL$1"; }
url()  { echo "http://127.0.0.1:$1/$2"; }

echo "== server-side prototype pollution =="
chk "sspp vulnerable -> confirmed"      "$(post /api/protopollution/test "{\"url\":\"$(url ${P[sspp-vuln]} api/me)\"}")" "d.get('vulnerable') and d.get('revertedAfterCleanup')"
chk "sspp safe -> not vulnerable"       "$(post /api/protopollution/test "{\"url\":\"$(url ${P[sspp-safe]} api/me)\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "sspp gzip -> inconclusive"         "$(post /api/protopollution/test "{\"url\":\"$(url ${P[sspp-gzip]} api/me)\"}")" "not d.get('vulnerable') and 'compressed' in (d.get('error') or '')"
chk "sspp constructor.prototype bypass -> confirmed (FN fix)" "$(post /api/protopollution/test "{\"url\":\"$(url ${P[sspp-ctor]} api/me)\"}")" "d.get('vulnerable') and d.get('polluteKey')=='constructor.prototype' and d.get('revertedAfterCleanup')"

echo "== host-header injection =="
chk "hh body-url -> injection"          "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-urlbody]} '')\"}")" "d.get('anyInjection')"
chk "hh Location -> injection"          "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-location]} '')\"}")" "d.get('anyInjection')"
chk "hh Host-line -> Location (HIGH tier)" "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-host-loc]} '')\"}")" "any(h.get('fromHostLine') and h.get('where')=='Location' for h in d.get('hits',[]))"
chk "hh fwd-header Location -> medium tier" "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-location]} '')\"}")" "any(h.get('inUrlContext') and not h.get('fromHostLine') for h in d.get('hits',[]))"
chk "hh unquoted // attr -> injection (FN fix)" "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-urlattr]} '')\"}")" "d.get('anyInjection')"
chk "hh bare -> reflected only"         "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-bare]} '')\"}")" "(not d.get('anyInjection')) and d.get('anyReflected')"
chk "hh safe -> nothing"                "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-safe]} '')\"}")" "d.get('ok') and not d.get('anyInjection') and not d.get('anyReflected')"
chk "hh comment -> not injection (FP)"  "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-comment]} '')\"}")" "not d.get('anyInjection')"
chk "hh cookie -> reflected"            "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-cookie]} '')\"}")" "d.get('anyReflected')"

echo "== SQL injection (core) =="
chk "sqli vulnerable -> confirmed"      "$(post /api/sqli/test "{\"url\":\"$(url ${P[sqli-vuln]} 'search?q=test')\"}")" "d.get('vulnerable')"
chk "sqli safe -> not vulnerable"       "$(post /api/sqli/test "{\"url\":\"$(url ${P[sqli-safe]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "sqli blind -> time-based confirmed" "$(post /api/sqli/test "{\"url\":\"$(url ${P[sqli-blind]} 'search?q=test')\",\"blind\":true}")" "d.get('vulnerable') and any(h.get('technique')=='time-based' for h in d.get('hits',[]))"
chk "sqli blind safe -> not vulnerable" "$(post /api/sqli/test "{\"url\":\"$(url ${P[sqli-safe]} 'search?q=test')\",\"blind\":true}")" "d.get('ok') and not d.get('vulnerable')"
chk "sqli WAF block (generic+403) -> NOT confirmed (FP fix)" "$(post /api/sqli/test "{\"url\":\"$(url ${P[sqli-waf]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== reflected XSS (core) =="
chk "xss vulnerable -> confirmed"       "$(post /api/xss/test "{\"url\":\"$(url ${P[xss-vuln]} '?q=test')\"}")" "d.get('vulnerable')"
chk "xss safe -> not vulnerable"        "$(post /api/xss/test "{\"url\":\"$(url ${P[xss-safe]} '?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "xss attr-context (raw, but in attribute) -> NOT vulnerable (headline FP fix)" "$(post /api/xss/test "{\"url\":\"$(url ${P[xss-attr]} '?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "xss raw reflection but nosniff+no-CT -> NOT vulnerable (sniff guard)" "$(post /api/xss/test "{\"url\":\"$(url ${P[xss-nosniff]} '?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== HTTP method audit =="
chk "method: advertised write methods -> INFO not medium (severity honesty)" "$(post /api/methods/test "{\"url\":\"$(url ${P[method-allow]} '')\"}")" "any(f['kind']=='dangerous-http-methods' and f['severity']=='info' for f in d.get('findings',[]))"
chk "method: advertised WebDAV -> webdav-enabled INFO" "$(post /api/methods/test "{\"url\":\"$(url ${P[method-allow]} '')\"}")" "any(f['kind']=='webdav-enabled' and f['severity']=='info' for f in d.get('findings',[]))"
chk "method: TRACE loopback echo -> XST confirmed" "$(post /api/methods/test "{\"url\":\"$(url ${P[method-trace]} '')\"}")" "d.get('traceEnabled') and any(f['kind']=='http-trace-enabled' for f in d.get('findings',[]))"
chk "method: request quoted mid-body (logging) -> NOT XST (offset-0 fix)" "$(post /api/methods/test "{\"url\":\"$(url ${P[method-trace-fp]} '')\"}")" "d.get('ok') and not d.get('traceEnabled')"
chk "method: Allow only on 405 (none on OPTIONS) -> harvested into allowed (FN fix)" "$(post /api/methods/test "{\"url\":\"$(url ${P[method-405]} '')\"}")" "'PUT' in d.get('allowed',[]) and 'DELETE' in d.get('allowed',[]) and any(f['kind']=='dangerous-http-methods' for f in d.get('findings',[]))"
chk "method: OPTIONS blocked but TRACK echoes -> XST confirmed via TRACK (FN fix)" "$(post /api/methods/test "{\"url\":\"$(url ${P[method-track]} '')\"}")" "d.get('ok') and d.get('traceEnabled') and any(f['kind']=='http-track-enabled' for f in d.get('findings',[]))"

echo "== CRLF / response splitting =="
chk "crlf split -> confirmed (parsed header)" "$(post /api/crlf/test "{\"url\":\"$(url ${P[crlf-vuln]} '?url=test')\"}")" "d.get('vulnerable')"
chk "crlf split, colon-less line -> confirmed (raw-bytes fallback)" "$(post /api/crlf/test "{\"url\":\"$(url ${P[crlf-colonless]} '?url=test')\"}")" "d.get('vulnerable')"
chk "crlf CR/LF stripped -> NOT vulnerable" "$(post /api/crlf/test "{\"url\":\"$(url ${P[crlf-safe]} '?url=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== open redirect (core) =="
chk "open-redirect vulnerable -> confirmed" "$(post /api/openredirect/test "{\"url\":\"$(url ${P[openredir-vuln]} '?url=test')\"}")" "d.get('vulnerable')"
chk "open-redirect safe -> not vulnerable"  "$(post /api/openredirect/test "{\"url\":\"$(url ${P[openredir-safe]} '?url=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "open-redirect Refresh header -> confirmed" "$(post /api/openredirect/test "{\"url\":\"$(url ${P[openredir-refresh]} '?url=test')\"}")" "d.get('vulnerable') and any(h.get('via')=='refresh-header' for h in d.get('hits',[]))"
chk "open-redirect JS location.assign -> confirmed" "$(post /api/openredirect/test "{\"url\":\"$(url ${P[openredir-js]} '?url=test')\"}")" "d.get('vulnerable') and any(h.get('via')=='js-location' for h in d.get('hits',[]))"
chk "open-redirect prose echo -> NOT flagged (FP fix)" "$(post /api/openredirect/test "{\"url\":\"$(url ${P[openredir-echo]} '?url=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== path traversal (core) =="
chk "path-traversal vulnerable -> confirmed" "$(post /api/pathtraversal/test "{\"url\":\"$(url ${P[pathtrav-vuln]} '?file=test')\"}")" "d.get('vulnerable')"
chk "path-traversal safe -> not vulnerable"  "$(post /api/pathtraversal/test "{\"url\":\"$(url ${P[pathtrav-safe]} '?file=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "path-traversal value-keyed template -> NOT confirmed (shaped-control FP fix)" "$(post /api/pathtraversal/test "{\"url\":\"$(url ${P[pathtrav-template]} '?file=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== CORS (core) =="
chk "cors reflects attacker origin"     "$(post /api/cors/test "{\"url\":\"$(url ${P[cors-vuln]} '')\"}")" "d.get('findingCount',0)>=1"
chk "cors safe -> no reflection"        "$(post /api/cors/test "{\"url\":\"$(url ${P[cors-safe]} '')\"}")" "d.get('ok') and d.get('findingCount',0)==0"
chk "cors trailing-dot flagged"         "$(post /api/cors/test "{\"url\":\"$(url ${P[cors-vuln]} '')\"}")" "any(p.get('label')=='trailing-dot' and p.get('severity') for p in d.get('probes',[]))"

echo "== verb tampering (core) =="
chk "verb tampering bypass found"       "$(post /api/verbtamper/test "{\"url\":\"$(url ${P[verb-vuln]} 'admin')\"}")" "d.get('bypassCount',0)>=1"
chk "verb ignored override NOT double-counted (FP fix)" "$(post /api/verbtamper/test "{\"url\":\"$(url ${P[verb-vuln]} 'admin')\"}")" "not any(b.get('technique','').startswith('override') for b in d.get('bypasses',[]))"
chk "verb tampering safe -> none"       "$(post /api/verbtamper/test "{\"url\":\"$(url ${P[verb-safe]} 'admin')\"}")" "d.get('ok') and d.get('bypassCount',0)==0"
chk "verb case-variation bypass found (FN fix)" "$(post /api/verbtamper/test "{\"url\":\"$(url ${P[verb-case]} 'admin')\"}")" "any(b.get('technique','').startswith('method-case') for b in d.get('bypasses',[]))"

echo "== SSTI (core) =="
chk "ssti vulnerable -> confirmed"      "$(post /api/ssti/test "{\"url\":\"$(url ${P[ssti-vuln]} '?q=x')\",\"param\":\"q\"}")" "d.get('confirmed')"
chk "ssti safe -> not confirmed"        "$(post /api/ssti/test "{\"url\":\"$(url ${P[ssti-safe]} '?q=x')\",\"param\":\"q\"}")" "d.get('ok') and not d.get('confirmed')"
chk "ssti calculator -> NOT confirmed (FP fix)" "$(post /api/ssti/test "{\"url\":\"$(url ${P[ssti-calc]} '?q=x')\",\"param\":\"q\"}")" "d.get('ok') and not d.get('confirmed')"

echo "== OS command injection (core) =="
chk "cmdi vulnerable -> confirmed"      "$(post /api/cmdi/test "{\"url\":\"$(url ${P[cmdi-vuln]} '?cmd=test')\",\"param\":\"cmd\"}")" "d.get('vulnerable')"
chk "cmdi arith-only -> NOT confirmed (FP fix)" "$(post /api/cmdi/test "{\"url\":\"$(url ${P[cmdi-arith]} '?cmd=test')\",\"param\":\"cmd\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "cmdi safe -> not vulnerable"       "$(post /api/cmdi/test "{\"url\":\"$(url ${P[cmdi-safe]} '?cmd=test')\",\"param\":\"cmd\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== NoSQL injection (core) =="
chk "nosqli vulnerable -> confirmed"    "$(post /api/nosqli/test "{\"url\":\"$(url ${P[nosqli-vuln]} '?q=test')\"}")" "d.get('vulnerable')"
chk "nosqli safe -> not vulnerable"     "$(post /api/nosqli/test "{\"url\":\"$(url ${P[nosqli-safe]} '?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "nosqli \$ne-name-deny -> NOT confirmed (2x2 FP fix)" "$(post /api/nosqli/test "{\"url\":\"$(url ${P[nosqli-namedeny]} '?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== IDOR / BOLA (core) =="
chk "idor vulnerable -> finding"        "$(post /api/idor/test "{\"url\":\"$(url ${P[idor-vuln]} '?id=100')\",\"idParam\":\"id\"}")" "d.get('findingCount',0)>=1"
chk "idor finding graded as enumeration LEAD, not confirmed (FP fix)" "$(post /api/idor/test "{\"url\":\"$(url ${P[idor-vuln]} '?id=100')\",\"idParam\":\"id\"}")" "d.get('severity')=='low' and d.get('kind')=='idor-enumerable'"
chk "idor safe -> no finding"           "$(post /api/idor/test "{\"url\":\"$(url ${P[idor-safe]} '?id=100')\",\"idParam\":\"id\"}")" "d.get('ok') and d.get('findingCount',0)==0"
chk "idor control-fetch fails -> fail-closed, no finding (FP fix)" "$(post /api/idor/test "{\"url\":\"$(url ${P[idor-ctrlfail]} '?id=100')\",\"idParam\":\"id\"}")" "d.get('findingCount',0)==0"
chk "idor zero-padded ids -> padding preserved -> finding (FN fix)" "$(post /api/idor/test "{\"url\":\"$(url ${P[idor-padded]} '?id=00042')\",\"idParam\":\"id\"}")" "d.get('findingCount',0)>=1"

echo "== XXE (core) =="
chk "xxe vulnerable -> confirmed"       "$(post /api/xxe/test "{\"url\":\"$(url ${P[xxe-vuln]} '')\"}")" "d.get('vulnerable')"
chk "xxe safe -> not vulnerable"        "$(post /api/xxe/test "{\"url\":\"$(url ${P[xxe-safe]} '')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "xxe XInclude -> confirmed (FN fix)" "$(post /api/xxe/test "{\"url\":\"$(url ${P[xxe-xinclude]} '')\"}")" "d.get('vulnerable')"
chk "xxe doctype-reject error page -> NOT confirmed (FP fix)" "$(post /api/xxe/test "{\"url\":\"$(url ${P[xxe-doctype-reject]} '')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== SSRF (core) =="
chk "ssrf vulnerable -> fetch confirmed"  "$(post /api/ssrf/test "{\"url\":\"$(url ${P[ssrf-vuln]} '?url=x')\"}")" "d.get('vulnerable') and d.get('hitCount',0)>=1"
chk "ssrf vuln -> IAM two-step confirms"  "$(post /api/ssrf/test "{\"url\":\"$(url ${P[ssrf-vuln]} '?url=x')\"}")" "any(h.get('technique')=='aws-imds-iam' for h in d.get('hits',[]))"
chk "ssrf safe -> no fetch"               "$(post /api/ssrf/test "{\"url\":\"$(url ${P[ssrf-safe]} '?url=x')\"}")" "d.get('ok') and not d.get('vulnerable') and d.get('hitCount',0)==0"
chk "ssrf shaped-control -> FP suppressed" "$(post /api/ssrf/test "{\"url\":\"$(url ${P[ssrf-fp]} '?url=x')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "ssrf decimal-IP bypass -> caught"    "$(post /api/ssrf/test "{\"url\":\"$(url ${P[ssrf-bypass]} '?url=x')\"}")" "d.get('vulnerable') and any(h.get('technique')=='aws-imds-decimal' for h in d.get('hits',[]))"
chk "ssrf internal service -> caught"     "$(post /api/ssrf/test "{\"url\":\"$(url ${P[ssrf-internal]} '?url=x')\"}")" "d.get('vulnerable') and any(h.get('kind')=='ssrf-internal' for h in d.get('hits',[]))"

echo "== insecure deserialization (core) =="
chk "deser Java sink -> confirmed Java"     "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-vuln]} '?data=x')\"}")" "d.get('vulnerable') and any(h.get('format')=='Java' for h in d.get('hits',[]))"
chk "deser param cap surfaces droppedParams (transparency fix)" "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-vuln]} '?data=x')\"}")" "len(d.get('droppedParams',[]))>=1"
chk "deser PHP sink -> confirmed PHP"       "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-php-vuln]} '?data=x')\"}")" "d.get('vulnerable') and any(h.get('format')=='PHP' for h in d.get('hits',[]))"
chk "deser Python sink -> confirmed Python" "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-python-vuln]} '?data=x')\"}")" "d.get('vulnerable') and any(h.get('format')=='Python' for h in d.get('hits',[]))"
chk "deser Ruby sink -> confirmed Ruby"     "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-ruby-vuln]} '?data=x')\"}")" "d.get('vulnerable') and any(h.get('format')=='Ruby' for h in d.get('hits',[]))"
chk "deser safe -> not vulnerable"          "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-safe]} '?data=x')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "deser shape-WAF -> FP suppressed"      "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-shapewaf]} '?data=x')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "deser always-errors -> not flagged"    "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-baseline]} '?data=x')\"}")" "not d.get('vulnerable')"
chk "deser raw-body sink -> confirmed Java"  "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-body-vuln]} '')\",\"location\":\"body\"}")" "d.get('vulnerable') and any(h.get('format')=='Java' for h in d.get('hits',[]))"
chk "deser raw-body safe -> not vulnerable"  "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-body-safe]} '')\",\"location\":\"body\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "deser cookie sink -> confirmed Java"    "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-cookie-vuln]} '')\",\"location\":\"cookie\"}")" "d.get('vulnerable') and any(h.get('format')=='Java' for h in d.get('hits',[]))"
chk "deser cookie safe -> not vulnerable"    "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-cookie-safe]} '')\",\"location\":\"cookie\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "deser form-field sink -> confirmed Java" "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-field-vuln]} '')\",\"location\":\"field\"}")" "d.get('vulnerable') and any(h.get('format')=='Java' for h in d.get('hits',[]))"
chk "deser form-field safe -> not vulnerable" "$(post /api/deser/test "{\"url\":\"$(url ${P[deser-field-safe]} '')\",\"location\":\"field\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== mass assignment (core) =="
chk "mass-assign vulnerable -> field bound" "$(post /api/massassign/test "{\"url\":\"$(url ${P[massassign-vuln]} '')\",\"body\":\"{\\\"username\\\":\\\"x\\\"}\",\"contentType\":\"application/json\"}")" "d.get('foundCount',0)>=1 and d.get('reflectionUsable')"
chk "mass-assign safe -> nothing bound"     "$(post /api/massassign/test "{\"url\":\"$(url ${P[massassign-safe]} '')\",\"body\":\"{\\\"username\\\":\\\"x\\\"}\",\"contentType\":\"application/json\"}")" "d.get('ok') and d.get('foundCount',0)==0 and d.get('reflectionUsable')"
chk "mass-assign 4xx validation-echo -> NOT bound (2xx-gate FP fix)" "$(post /api/massassign/test "{\"url\":\"$(url ${P[massassign-validecho]} '')\",\"body\":\"{\\\"username\\\":\\\"x\\\"}\",\"contentType\":\"application/json\"}")" "d.get('ok') and d.get('foundCount',0)==0 and d.get('reflectionUsable')"

echo "== LDAP injection =="
chk "ldap vulnerable -> confirmed"      "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-vuln]} 'search?q=test')\"}")" "d.get('vulnerable')"
chk "ldap safe -> not vulnerable"       "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-safe]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "ldap baseline-errors -> not flagged" "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-baseline]} 'search?q=test')\"}")" "not d.get('vulnerable')"
chk "ldap WAF block (generic+403) -> NOT confirmed (FP fix)" "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-waf]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== XPath injection =="
chk "xpath vulnerable -> confirmed"     "$(post /api/xpathi/test "{\"url\":\"$(url ${P[xpath-vuln]} 'search?q=test')\"}")" "d.get('vulnerable')"
chk "xpath safe -> not vulnerable"      "$(post /api/xpathi/test "{\"url\":\"$(url ${P[xpath-safe]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "xpath WAF block (generic+403) -> NOT confirmed (FP fix)" "$(post /api/xpathi/test "{\"url\":\"$(url ${P[xpath-waf]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== content discovery =="
CB="$(post /api/content/discover "{\"url\":\"$(url ${P[content-found]} '')\"}")"
chk "content finds /admin, soft-404 calibrated" "$CB" "d.get('softNotFoundStatus')==404 and any(h['path'].endswith('/admin') and h['status']==200 for h in d.get('hits',[]))"

echo "== cross-site WebSocket hijacking (CSWSH) =="
chk "cswsh authed cross-origin, no-cookie baseline refused -> CONFIRMED CSWSH" "$(post /api/cswsh/test "{\"url\":\"$(url ${P[cswsh-vuln]} '')\",\"headers\":{\"Cookie\":\"session=abc\"}}")" "d.get('vulnerable') and d.get('isWebSocket')"
chk "cswsh public, NO credential -> Origin-not-validated LEAD (FP fix)" "$(post /api/cswsh/test "{\"url\":\"$(url ${P[cswsh-open]} '')\"}")" "d.get('ok') and not d.get('vulnerable') and d.get('originNotValidated')"
chk "cswsh public + cookie, no-cookie baseline ALSO 101s -> downgrade to LEAD (authed-baseline confirm)" "$(post /api/cswsh/test "{\"url\":\"$(url ${P[cswsh-open]} '')\",\"headers\":{\"Cookie\":\"session=abc\"}}")" "d.get('ok') and not d.get('vulnerable') and d.get('originNotValidated')"
chk "cswsh endsWith(host) allow-list accepts attacker.<host> subdomain -> still flagged (FN fix)" "$(post /api/cswsh/test "{\"url\":\"$(url ${P[cswsh-subdomain]} '')\"}")" "d.get('ok') and d.get('originNotValidated') and not d.get('originValidated')"
chk "cswsh safe -> origin validated"            "$(post /api/cswsh/test "{\"url\":\"$(url ${P[cswsh-safe]} '')\"}")" "d.get('ok') and not d.get('vulnerable') and d.get('originValidated')"

echo "== active JWT attacks =="
# Mint a valid HS256 token signed with the given secret (matches the mock).
mint_jwt() { python -c "import hmac,hashlib,base64,json,sys
def e(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
h=e(json.dumps({'alg':'HS256','typ':'JWT'},separators=(',',':')).encode())
p=e(json.dumps({'sub':'alice','role':'user'},separators=(',',':')).encode())
s=e(hmac.new(sys.argv[1].encode(),(h+'.'+p).encode(),hashlib.sha256).digest())
print(h+'.'+p+'.'+s)" "$1"; }
JTOK="$(mint_jwt 'Zx9-strong-test-secret-not-in-any-wordlist-8f3a1b2c')"   # matches JWT_STRONG
JTOK_WEAK="$(mint_jwt 'secret')"
chk "jwt safe -> not vulnerable"        "$(post /api/jwt/test "{\"url\":\"$(url ${P[jwt-safe]} '')\",\"token\":\"$JTOK\"}")" "d.get('ok') and d.get('calibrated') and not d.get('vulnerable')"
chk "jwt alg:none accepted -> bypass"   "$(post /api/jwt/test "{\"url\":\"$(url ${P[jwt-algnone]} '')\",\"token\":\"$JTOK\"}")" "d.get('vulnerable') and any(h.get('attack')=='alg-none' for h in d.get('hits',[]))"
chk "jwt signature-not-verified -> bypass" "$(post /api/jwt/test "{\"url\":\"$(url ${P[jwt-noverify]} '')\",\"token\":\"$JTOK\"}")" "d.get('vulnerable') and any(h.get('attack')=='signature-not-verified' for h in d.get('hits',[]))"
chk "jwt weak-secret -> bypass"         "$(post /api/jwt/test "{\"url\":\"$(url ${P[jwt-weak]} '')\",\"token\":\"$JTOK_WEAK\"}")" "d.get('vulnerable') and any(h.get('attack')=='weak-secret' for h in d.get('hits',[]))"
# RS256 token (placeholder sig the mock treats as a valid RSA sig) + the fake pubkey.
mint_rs() { python -c "import base64,json,sys
def e(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
h=e(json.dumps({'alg':'RS256','typ':'JWT'},separators=(',',':')).encode())
p=e(json.dumps({'sub':'alice','role':'user'},separators=(',',':')).encode())
print(h+'.'+p+'.'+sys.argv[1])" "$1"; }
JTOK_RS="$(mint_rs 'ZmFrZXJzc2lnbmF0dXJlMTIz')"
JPUB='nullock-fake-rsa-public-key-for-confusion-test'
chk "jwt RS->HS confusion -> bypass"    "$(post /api/jwt/test "{\"url\":\"$(url ${P[jwt-algconfusion]} '')\",\"token\":\"$JTOK_RS\",\"publicKey\":\"$JPUB\"}")" "d.get('vulnerable') and any(h.get('attack')=='alg-confusion' for h in d.get('hits',[]))"
chk "jwt RS verifier safe -> not vulnerable" "$(post /api/jwt/test "{\"url\":\"$(url ${P[jwt-rs-safe]} '')\",\"token\":\"$JTOK_RS\",\"publicKey\":\"$JPUB\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "jwt carrier fan-out finds cookie bypass" "$(post /api/jwt/test "{\"url\":\"$(url ${P[jwt-cookie-noverify]} '')\",\"token\":\"$JTOK\"}")" "d.get('vulnerable') and any(h.get('carrier','').startswith('cookie:jwt') for h in d.get('hits',[]))"
chk "jwt body-bearing POST route -> bypass" "$(post /api/jwt/test "{\"url\":\"$(url ${P[jwt-body-noverify]} '')\",\"token\":\"$JTOK\",\"method\":\"POST\",\"body\":\"x=1\",\"contentType\":\"application/x-www-form-urlencoded\"}")" "d.get('vulnerable') and d.get('calibrated') and any(h.get('attack')=='signature-not-verified' for h in d.get('hits',[]))"

echo "== web cache poisoning =="
chk "cache keyed+reflected -> confirmed" "$(post /api/cache/poison "{\"url\":\"$(url ${P[cache-keyed-vuln]} '')\"}")" "d.get('ok') and d.get('anyConfirmed')"
chk "cache unkeyed buster -> ABORT, no inject" "$(post /api/cache/poison "{\"url\":\"$(url ${P[cache-unkeyed]} '')\"}")" "not d.get('anyConfirmed') and 'unkeyed' in (d.get('error') or '') and d.get('hitCount',0)==0 and d.get('requestsSent')==3"
chk "cache silent (no hit signal) -> fail-closed ABORT (headline FP/safety fix)" "$(post /api/cache/poison "{\"url\":\"$(url ${P[cache-silent]} '')\"}")" "not d.get('anyConfirmed') and 'cache-hit signal' in (d.get('error') or '') and d.get('hitCount',0)==0 and d.get('requestsSent')==2"

echo "== web cache deception =="
chk "cache-deception path confusion -> hit (cacheable/high)" "$(post /api/cachedeception/test "{\"url\":\"$(url ${P[cd-vuln]} 'account')\"}")" "d.get('hitCount',0)>=1 and d.get('anyCacheable') and not d.get('catchAll')"
chk "cache-deception catch-all SPA -> suppressed (FP fix)" "$(post /api/cachedeception/test "{\"url\":\"$(url ${P[cd-catchall]} 'account')\"}")" "d.get('catchAll') and d.get('hitCount',0)==0"
chk "cache-deception max-age=0 -> hit but NOT cacheable (severity FP fix)" "$(post /api/cachedeception/test "{\"url\":\"$(url ${P[cd-maxage0]} 'account')\"}")" "d.get('hitCount',0)>=1 and not d.get('anyCacheable') and not d.get('catchAll')"

echo "== subdomain takeover =="
chk "takeover branded fingerprint -> candidate" "$(post /api/takeover/test "{\"url\":\"$(url ${P[takeover-vuln]} '')\"}")" "d.get('hitCount',0)>=1 and any(h.get('service')=='Fastly' for h in d.get('hits',[]))"
chk "takeover stock Apache 404 -> NOT flagged (FP fix)" "$(post /api/takeover/test "{\"url\":\"$(url ${P[takeover-apache404]} '')\"}")" "d.get('ok') and d.get('hitCount',0)==0"

echo "== race conditions =="
chk "race limited-use leak (wins + 409s) -> suspected" "$(post /api/race/test "{\"url\":\"$(url ${P[race-vuln]} 'redeem')\",\"count\":10}")" "d.get('raceSuspected') and d.get('successCount',0)>1"
chk "race atomic (1 win + 409s) -> NOT suspected" "$(post /api/race/test "{\"url\":\"$(url ${P[race-atomic]} 'redeem')\",\"count\":10}")" "not d.get('raceSuspected') and d.get('successCount')==1"
chk "race over-grant (all writes win) -> over-grant suspected (FN fix)" "$(post /api/race/test "{\"url\":\"$(url ${P[race-overgrant]} 'redeem')\",\"count\":10}")" "d.get('overGrantSuspected') and not d.get('raceSuspected')"
chk "race unrelated 403s -> NOT a race (rejection-bucket FP fix)" "$(post /api/race/test "{\"url\":\"$(url ${P[race-noise]} 'redeem')\",\"count\":10}")" "not d.get('raceSuspected') and d.get('otherClientError',0)>0"

echo "== parameter mining =="
chk "param reflected -> found" "$(post /api/paramminer "{\"url\":\"$(url ${P[paramminer-reflect]} '')\",\"wordlist\":[\"q\",\"foo\",\"bar\",\"baz\"]}")" "any(f.get('name')=='q' and f.get('reflected') for f in d.get('found',[])) and d.get('reflectionSignalUsable')"
chk "param status-flip -> found (re-confirmed, FP-hardened)" "$(post /api/paramminer "{\"url\":\"$(url ${P[paramminer-status]} '')\",\"wordlist\":[\"admin\",\"foo\",\"bar\",\"baz\"]}")" "any(f.get('name')=='admin' and f.get('signal')=='status-change' for f in d.get('found',[]))"
chk "param echo-all -> reflection signal disabled (junk-control)" "$(post /api/paramminer "{\"url\":\"$(url ${P[paramminer-echoall]} '')\",\"wordlist\":[\"q\",\"x\"]}")" "not d.get('reflectionSignalUsable')"

echo "== sensitive-file exposure =="
chk "exposure git/config -> found" "$(post /api/exposure/scan "{\"url\":\"$(url ${P[exposure-vuln]} '')\"}")" "any(h.get('path')=='/.git/config' for h in d.get('hits',[])) and not d.get('catchAll')"
chk "exposure real .env -> found (redacted)" "$(post /api/exposure/scan "{\"url\":\"$(url ${P[exposure-env]} '')\"}")" "any(h.get('path')=='/.env' and 'redacted' in (h.get('evidence') or '') for h in d.get('hits',[]))"
chk "exposure catch-all 200 shell -> NOTHING flagged (soft-404 + rejectHtml FP fix)" "$(post /api/exposure/scan "{\"url\":\"$(url ${P[exposure-catchall]} '')\"}")" "d.get('catchAll') and d.get('hitCount',0)==0"

echo "== client-side secret exposure =="
chk "secret high-entropy assigned -> found" "$(post /api/secrets/scan "{\"url\":\"$(url ${P[secrets-vuln]} '')\",\"followScripts\":false}")" "any(h.get('type')=='assigned-secret' for h in d.get('hits',[]))"
chk "secret placeholder/example value -> NOT flagged (looksPlaceholder FP fix)" "$(post /api/secrets/scan "{\"url\":\"$(url ${P[secrets-example]} '')\",\"followScripts\":false}")" "d.get('ok') and d.get('hitCount',0)==0"

echo "== HTTP fingerprint =="
chk "fingerprint prose mention -> NO false Joomla/Drupal tech (CVE-FP fix)" "$(post /api/fingerprint "{\"url\":\"$(url ${P[fp-prose]} '')\"}")" "not any(t.get('name') in ('Joomla','Drupal') for t in d.get('tech',[]))"
chk "fingerprint Joomla generator meta -> detected with version" "$(post /api/fingerprint "{\"url\":\"$(url ${P[fp-real]} '')\"}")" "any(t.get('name')=='Joomla' and t.get('version')=='3.9.28' for t in d.get('tech',[]))"

echo "== security-header / CSP audit =="
chk "hdr: CSP without script-src/default-src -> csp-no-script-restriction HIGH (FN fix)" "$(post /api/headers/audit "{\"url\":\"$(url ${P[hdr-noscript]} '')\"}")" "any(f['key']=='csp-no-script-restriction' and f['severity']=='high' for f in d.get('findings',[]))"
chk "hdr: script-src https://* -> csp-wildcard-source (scheme-wildcard FN fix)" "$(post /api/headers/audit "{\"url\":\"$(url ${P[hdr-wildcard]} '')\"}")" "any(f['key']=='csp-wildcard-source' for f in d.get('findings',[]))"
chk "hdr: X-Frame-Options ALLOWALL -> clickjacking-missing (permissive XFO FN fix)" "$(post /api/headers/audit "{\"url\":\"$(url ${P[hdr-xfo-allowall]} '')\"}")" "any(f['key']=='clickjacking-missing' for f in d.get('findings',[]))"

echo "== token sequencer =="
chk "seq: 8-hex tokens (~32 effective bits) -> NOT looks-random (keyspace)" "$(post /api/sequencer/analyze "{\"tokens\":[\"1a2b3c4d\",\"9f8e7d6c\",\"00112233\",\"deadbeef\",\"cafe1234\",\"5566aabb\",\"0f1e2d3c\",\"98765432\",\"abcdef01\",\"13579bdf\"]}")" "d.get('verdict')!='looks-random' and d.get('score',100)<80"
chk "seq: 40-hex tokens (~160 bits) -> looks-random (no alphabet penalty)" "$(post /api/sequencer/analyze "{\"tokens\":[\"a3f19c4b7e2d8061f5a9c3e7b1d4082f6c9a1e35\",\"5e1d9a7c3f0b6248e9d1a4c7f2b8053196e4d7a0\",\"0c7b2e9f4a1d6385c0e9b2f7a4d18305e6c1b9f2\",\"f29a4d7c1e0b58369c2f7a4d1e8b0537a6c9f1e4\",\"7b1e4c9a2f8d05637e1c4a9f2d6b80531a7e4c92\",\"2d8f1a4c7e9b06352f8d1a4c7e0b9536a2f8d1c4\"]}")" "d.get('verdict')=='looks-random'"
chk "seq: decimal counter crossing 99->100 -> sequential (base auto-detect)" "$(post /api/sequencer/analyze "{\"tokens\":[\"97\",\"98\",\"99\",\"100\",\"101\",\"102\"]}")" "d.get('sequential',{}).get('looksSequential')"

echo "== WAF / CDN / LB detection =="
chk "waf Cloudflare + Incapsula detected (multi-vendor)" "$(post /api/waf/detect "{\"url\":\"$(url ${P[waf-detect]} '')\"}")" "any(x['name']=='Cloudflare' for x in d.get('detections',[])) and any(x['name']=='Imperva Incapsula' for x in d.get('detections',[]))"
chk "waf Cloudflare deduped to one row (cf-ray beats Server)" "$(post /api/waf/detect "{\"url\":\"$(url ${P[waf-detect]} '')\"}")" "len([x for x in d.get('detections',[]) if x['name']=='Cloudflare'])==1"
chk "waf BIGipServer in cookie VALUE -> NOT F5 (cookie NAME-only)" "$(post /api/waf/detect "{\"url\":\"$(url ${P[waf-detect]} '')\"}")" "not any(x['name']=='F5 BIG-IP' for x in d.get('detections',[]))"
chk "waf clean origin -> zero detections (no FP)" "$(post /api/waf/detect "{\"url\":\"$(url ${P[waf-clean]} '')\"}")" "d.get('ok') and d.get('detectionCount')==0"

echo "== HTTP/3 detection =="
chk "h3 advertised -> detected"         "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-adv]} '')\"}")" "d.get('advertisesHttp3') and 'h3' in d.get('http3Versions',[])"
chk "h3 h2-only -> not advertised"      "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-h2only]} '')\"}")" "not d.get('advertisesHttp3')"
chk "h3 no Alt-Svc -> not advertised"   "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-none]} '')\"}")" "d.get('ok') and not d.get('advertisesHttp3')"
chk "h3 clear -> not advertised"        "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-clear]} '')\"}")" "not d.get('advertisesHttp3')"

echo "== OAST out-of-band confirmation (SSRF / RCE / XXE) =="
# Each blast mints fresh random tokens, injects one battery's OOB payloads, and
# fires them. A vulnerable mock makes the out-of-band request to our sink; the
# correlator confirms by matching the pre-registered token. We assert a callback
# arrived for a token from THIS blast (token-precise -> immune to other
# batteries' async callback tails) and that a safe target yields none. (Log4Shell
# confirms via the DNS sink, a different channel -- not covered by this HTTP mock.)
oast_battery() {  # $1=port-key  $2=flags  -> echoes 1 if a callback for one of this blast's tokens landed
  local resp toks i
  resp="$(post /api/oast/blast "{\"url\":\"$(url ${P[$1]} '')\",$2}")"
  toks="$(printf '%s' "$resp" | python -c "import json,sys
try: print('|'.join(v.get('token','') for v in json.load(sys.stdin).get('vectors',[])))
except Exception: print('')")"
  [ -z "$toks" ] && { echo 0; return; }
  for i in $(seq 1 16); do
    if curl -sS "${HDR[@]}" "$BASEURL/api/oast/poll?since=0" 2>/dev/null | TOKS="$toks" python -c "import json,sys,os
toks=set(os.environ['TOKS'].split('|'))
hits={h.get('token','') for h in json.load(sys.stdin).get('hits',[])}
sys.exit(0 if (toks & hits) else 1)"; then echo 1; return; fi
    sleep 0.5
  done
  echo 0
}
RCEFLAGS='"ssrf":false,"xxe":false,"log4shell":false,"rce":true'
SSRFLAGS='"ssrf":true,"xxe":false,"log4shell":false,"rce":false'
XXEFLAGS='"ssrf":false,"xxe":true,"log4shell":false,"rce":false'
chk "oast SSRF OOB -> callback confirmed"      "{\"v\":$(oast_battery oast-vuln "$SSRFLAGS")}" "d.get('v')==1"
chk "oast blind-RCE OOB -> callback confirmed" "{\"v\":$(oast_battery oast-vuln "$RCEFLAGS")}" "d.get('v')==1"
chk "oast blind-XXE OOB -> callback confirmed" "{\"v\":$(oast_battery oast-vuln "$XXEFLAGS")}" "d.get('v')==1"
chk "oast safe target -> no callback"          "{\"v\":$(oast_battery oast-safe "$RCEFLAGS")}" "d.get('v')==0"

# Log4Shell confirms via the DNS sink, not the HTTP sink, so assert on the
# isolated snapshot.oast.dnsHits counter (only this mock fires DNS -> the
# cumulative counter is safe here). A vulnerable JNDI resolver looks up the
# callback host; a safe target makes no DNS query.
oast_dnshits() { curl -sS "${HDR[@]}" "$BASEURL/api/snapshot" 2>/dev/null | python -c "import json,sys
try: print(json.load(sys.stdin).get('oast',{}).get('dnsHits',0))
except Exception: print(-1)"; }
l4_safe_before="$(oast_dnshits)"
post /api/oast/blast "{\"url\":\"$(url ${P[oastlog4-safe]} '')\",\"log4shell\":true,\"ssrf\":false,\"xxe\":false,\"rce\":false}" >/dev/null
sleep 2
chk "oast log4shell-safe -> no DNS hit"        "{\"a\":$(oast_dnshits),\"b\":$l4_safe_before}" "d.get('a')==d.get('b')"
l4_before="$(oast_dnshits)"
post /api/oast/blast "{\"url\":\"$(url ${P[oastlog4-vuln]} '')\",\"log4shell\":true,\"ssrf\":false,\"xxe\":false,\"rce\":false}" >/dev/null
l4_got=0
for _ in $(seq 1 16); do
  now="$(oast_dnshits)"
  if [ "$now" -gt "$l4_before" ] 2>/dev/null; then l4_got=1; break; fi
  sleep 0.5
done
chk "oast log4shell DNS OOB -> callback landed" "{\"got\":$l4_got}" "d.get('got')==1"

echo ""
echo "probe_smoke: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
