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
import http.server, socketserver, sys, threading, time, json, gzip
from urllib.parse import urlparse, parse_qs
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
            if mode == 'sspp-vuln':
                try: p = json.loads(raw)
                except Exception: p = {}
                if isinstance(p, dict) and isinstance(p.get('__proto__'), dict) and 'json spaces' in p['__proto__']:
                    try: state['spaces'] = int(p['__proto__']['json spaces'])
                    except Exception: pass
            self._send(200, b'{"ok":true}', 'application/json')
        def do_GET(self):
            q = parse_qs(urlparse(self.path).query)
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
                if mode == 'hh-location':
                    self._send(302, b'', 'text/html', [('Location', 'https://%s/welcome' % xfh)]); return
                if mode == 'hh-cookie':
                    self._send(200, b'<html>ok</html>', 'text/html',
                               [('Set-Cookie', 'sid=1; Domain=%s; Path=/' % xfh)]); return
                if mode == 'hh-urlbody':  b = ('<a href="https://%s/reset?token=abc">r</a>' % xfh).encode()
                elif mode == 'hh-bare':   b = ('<p>requested host = %s</p>' % xfh).encode()
                elif mode == 'hh-comment':b = ('<!-- proxied via //%s internal -->' % xfh).encode()
                else:                     b = b'<a href="https://canonical.example/r">x</a>'
                self._send(200, b, 'text/html'); return
            if mode.startswith('ldap'):
                err = b'<html>javax.naming.directory.InvalidSearchFilterException: invalid search filter</html>'
                ok  = b'<html>0 results</html>'
                val = q.get('q', [''])[0]
                if mode == 'ldap-baseline': self._send(200, err); return
                if mode == 'ldap-vuln':     self._send(200, err if ('(' in val or ')' in val) else ok); return
                self._send(200, ok); return
            if mode.startswith('xpath'):
                err = b'<html>javax.xml.xpath.XPathExpressionException: invalid XPath expression</html>'
                ok  = b'<html>0 nodes</html>'
                val = q.get('q', [''])[0]
                brk = any(c in val for c in "'\"])")
                self._send(200, err if (mode == 'xpath-vuln' and brk) else ok); return
            if mode.startswith('h3'):
                alt = {'h3-adv': 'h3=":443"; ma=86400, h3-29=":443", h2=":443"',
                       'h3-h2only': 'h2=":443"; ma=3600',
                       'h3-clear': 'clear'}.get(mode)
                extra = [('Alt-Svc', alt)] if alt is not None else []
                self._send(200, b'ok\n', 'text/plain', extra); return
            if mode.startswith('content'):
                # 404 everything (incl. the random calibration paths) except a
                # single real path, so discovery surfaces exactly /admin.
                p = urlparse(self.path).path.rstrip('/')
                if p == '/admin': self._send(200, b'<html>Admin Panel login</html>')
                else:             self._send(404, b'<html>404 not found</html>')
                return
            if mode.startswith('sqli'):
                # Error-based: an unbalanced quote (odd count) breaks the query;
                # the breaker has 1 quote (odd), the balanced control has 2 (even).
                val = q.get('q', [''])[0]
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
                if mode != 'xss-vuln':
                    val = val.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                self._send(200, ('<html><body>Results for: %s</body></html>' % val).encode())
                return
            if mode.startswith('openredir'):
                # Vulnerable mock reflects the redirect param straight into the
                # Location header; the probe flags it resolving to its sentinel.
                val = q.get('url', [''])[0]
                if mode == 'openredir-vuln' and '\n' not in val and '\r' not in val:
                    self.send_response(302); self.send_header('Location', val)
                    self.send_header('Content-Length', '0'); self.end_headers()
                else:
                    self._send(200, b'<html>home</html>')
                return
            if mode.startswith('pathtrav'):
                # Vulnerable mock returns a passwd-shaped body when the param
                # carries a traversal/passwd payload; the probe matches the
                # root:x:0:0: signature.
                val = q.get('file', [''])[0]
                if mode == 'pathtrav-vuln' and ('..' in val or 'passwd' in val):
                    self._send(200, b'root:x:0:0:root:/root:/bin/bash\n'
                                    b'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n', 'text/plain')
                else:
                    self._send(200, b'<html>file not found</html>')
                return
            self._send(200, b'ok\n', 'text/plain')
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
MODES=(sspp-vuln sspp-safe sspp-gzip
       hh-urlbody hh-location hh-bare hh-safe hh-comment hh-cookie
       sqli-vuln sqli-safe
       xss-vuln xss-safe
       openredir-vuln openredir-safe
       pathtrav-vuln pathtrav-safe
       ldap-vuln ldap-safe ldap-baseline
       xpath-vuln xpath-safe
       content-found
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

echo "== host-header injection =="
chk "hh body-url -> injection"          "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-urlbody]} '')\"}")" "d.get('anyInjection')"
chk "hh Location -> injection"          "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-location]} '')\"}")" "d.get('anyInjection')"
chk "hh bare -> reflected only"         "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-bare]} '')\"}")" "(not d.get('anyInjection')) and d.get('anyReflected')"
chk "hh safe -> nothing"                "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-safe]} '')\"}")" "d.get('ok') and not d.get('anyInjection') and not d.get('anyReflected')"
chk "hh comment -> not injection (FP)"  "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-comment]} '')\"}")" "not d.get('anyInjection')"
chk "hh cookie -> reflected"            "$(post /api/hostheader/test "{\"url\":\"$(url ${P[hh-cookie]} '')\"}")" "d.get('anyReflected')"

echo "== SQL injection (core) =="
chk "sqli vulnerable -> confirmed"      "$(post /api/sqli/test "{\"url\":\"$(url ${P[sqli-vuln]} 'search?q=test')\"}")" "d.get('vulnerable')"
chk "sqli safe -> not vulnerable"       "$(post /api/sqli/test "{\"url\":\"$(url ${P[sqli-safe]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== reflected XSS (core) =="
chk "xss vulnerable -> confirmed"       "$(post /api/xss/test "{\"url\":\"$(url ${P[xss-vuln]} '?q=test')\"}")" "d.get('vulnerable')"
chk "xss safe -> not vulnerable"        "$(post /api/xss/test "{\"url\":\"$(url ${P[xss-safe]} '?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== open redirect (core) =="
chk "open-redirect vulnerable -> confirmed" "$(post /api/openredirect/test "{\"url\":\"$(url ${P[openredir-vuln]} '?url=test')\"}")" "d.get('vulnerable')"
chk "open-redirect safe -> not vulnerable"  "$(post /api/openredirect/test "{\"url\":\"$(url ${P[openredir-safe]} '?url=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== path traversal (core) =="
chk "path-traversal vulnerable -> confirmed" "$(post /api/pathtraversal/test "{\"url\":\"$(url ${P[pathtrav-vuln]} '?file=test')\"}")" "d.get('vulnerable')"
chk "path-traversal safe -> not vulnerable"  "$(post /api/pathtraversal/test "{\"url\":\"$(url ${P[pathtrav-safe]} '?file=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== LDAP injection =="
chk "ldap vulnerable -> confirmed"      "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-vuln]} 'search?q=test')\"}")" "d.get('vulnerable')"
chk "ldap safe -> not vulnerable"       "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-safe]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "ldap baseline-errors -> not flagged" "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-baseline]} 'search?q=test')\"}")" "not d.get('vulnerable')"

echo "== XPath injection =="
chk "xpath vulnerable -> confirmed"     "$(post /api/xpathi/test "{\"url\":\"$(url ${P[xpath-vuln]} 'search?q=test')\"}")" "d.get('vulnerable')"
chk "xpath safe -> not vulnerable"      "$(post /api/xpathi/test "{\"url\":\"$(url ${P[xpath-safe]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"

echo "== content discovery =="
CB="$(post /api/content/discover "{\"url\":\"$(url ${P[content-found]} '')\"}")"
chk "content finds /admin, soft-404 calibrated" "$CB" "d.get('softNotFoundStatus')==404 and any(h['path'].endswith('/admin') and h['status']==200 for h in d.get('hits',[]))"

echo "== HTTP/3 detection =="
chk "h3 advertised -> detected"         "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-adv]} '')\"}")" "d.get('advertisesHttp3') and 'h3' in d.get('http3Versions',[])"
chk "h3 h2-only -> not advertised"      "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-h2only]} '')\"}")" "not d.get('advertisesHttp3')"
chk "h3 no Alt-Svc -> not advertised"   "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-none]} '')\"}")" "d.get('ok') and not d.get('advertisesHttp3')"
chk "h3 clear -> not advertised"        "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-clear]} '')\"}")" "not d.get('advertisesHttp3')"

echo ""
echo "probe_smoke: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
