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
            if mode.startswith('h3'):
                alt = {'h3-adv': 'h3=":443"; ma=86400, h3-29=":443", h2=":443"',
                       'h3-h2only': 'h2=":443"; ma=3600',
                       'h3-clear': 'clear'}.get(mode)
                extra = [('Alt-Svc', alt)] if alt is not None else []
                self._send(200, b'ok\n', 'text/plain', extra); return
            self._send(200, b'ok\n', 'text/plain')
        def log_message(self, *a): pass
    return H
args = sys.argv[1:]
for i in range(0, len(args), 2):
    port, mode = int(args[i]), args[i + 1]
    threading.Thread(target=socketserver.TCPServer(('127.0.0.1', port), make(mode)).serve_forever,
                     daemon=True).start()
while True: time.sleep(1)
PY

# Assign a port per mock mode.
BASE=$(( (RANDOM % 2000) + 5300 ))
declare -A P
i=0
for m in sspp-vuln sspp-safe sspp-gzip \
         hh-urlbody hh-location hh-bare hh-safe hh-comment hh-cookie \
         ldap-vuln ldap-safe ldap-baseline \
         h3-adv h3-h2only h3-none h3-clear; do
  P[$m]=$(( BASE + i )); i=$(( i + 1 ))
done

MOCK_ARGS=()
for m in "${!P[@]}"; do MOCK_ARGS+=( "${P[$m]}" "$m" ); done
python "$MOCK" "${MOCK_ARGS[@]}" & MOCK_PID=$!

CTL=$(( (RANDOM % 4000) + 21000 ))
PROJ="$(mktemp -d /tmp/nullock-probe-proj.XXXXXX)"
"$EXE" --headless --control-port="$CTL" --proxy-port="$(( CTL + 1 ))" --project="$PROJ" --no-update-check &
APP_PID=$!
cleanup() { kill "$MOCK_PID" "$APP_PID" 2>/dev/null; rm -f "$MOCK"; rm -rf "$PROJ"; }
trap cleanup EXIT

BASEURL="http://127.0.0.1:$CTL"
HDR=(-H "Content-Type: application/json" -H "Origin: $BASEURL" -H "X-Nullock-UI: 1")
for _ in $(seq 1 40); do curl -sS --max-time 2 "$BASEURL/api/snapshot" >/dev/null 2>&1 && break; sleep 0.5; done
sleep 1

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

echo "== LDAP injection =="
chk "ldap vulnerable -> confirmed"      "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-vuln]} 'search?q=test')\"}")" "d.get('vulnerable')"
chk "ldap safe -> not vulnerable"       "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-safe]} 'search?q=test')\"}")" "d.get('ok') and not d.get('vulnerable')"
chk "ldap baseline-errors -> not flagged" "$(post /api/ldapi/test "{\"url\":\"$(url ${P[ldap-baseline]} 'search?q=test')\"}")" "not d.get('vulnerable')"

echo "== HTTP/3 detection =="
chk "h3 advertised -> detected"         "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-adv]} '')\"}")" "d.get('advertisesHttp3') and 'h3' in d.get('http3Versions',[])"
chk "h3 h2-only -> not advertised"      "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-h2only]} '')\"}")" "not d.get('advertisesHttp3')"
chk "h3 no Alt-Svc -> not advertised"   "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-none]} '')\"}")" "d.get('ok') and not d.get('advertisesHttp3')"
chk "h3 clear -> not advertised"        "$(post /api/http3/detect "{\"url\":\"$(url ${P[h3-clear]} '')\"}")" "not d.get('advertisesHttp3')"

echo ""
echo "probe_smoke: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
