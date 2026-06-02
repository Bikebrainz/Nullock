#!/usr/bin/env bash
# CI recipe: proxy a target through Nullock, run the active probe across
# every captured row, export findings as SARIF, fail the build on any
# high-severity finding.
#
# Usage:  ci-scan-and-sarif.sh <target-url> [<output-sarif-path>]
#
# Requires:
#   - NullockApp running (recommended: --headless --ndjson)
#   - curl, jq
#   - the CA cert from $APPDATA/Nullock/Nullock/ca/ca.pem trusted in
#     whatever client you'll point at the proxy
#
# Designed to drop into a GitHub Actions step:
#
#   - name: Run Nullock active scan
#     run: ./examples/ci-scan-and-sarif.sh https://staging.example.com findings.sarif
#   - name: Upload SARIF
#     if: always()
#     uses: github/codeql-action/upload-sarif@v3
#     with: { sarif_file: findings.sarif }

set -euo pipefail

TARGET=${1:?"usage: $0 <target-url> [<sarif-path>]"}
SARIF_OUT=${2:-findings.sarif}
API=${NULLOCK_API:-http://127.0.0.1:17777}
PROXY=${HTTP_PROXY:-http://127.0.0.1:8080}
CLI="$(dirname "$0")/../bin/nullock"

echo "[+] starting from clean slate"
"$CLI" project clear-history >/dev/null
curl -sS -X POST -H "Origin: $API" "$API/api/findings/clear" >/dev/null

echo "[+] crawling $TARGET through proxy $PROXY"
# Replace with your real test client. This minimal crawl hits the
# landing page + common attack-surface paths so the active probe has
# something to chew on.
for path in / /login /api /api/v1 /admin /docs '/?q=test' '/search?q=test'; do
    curl -ks --max-time 10 --proxy "$PROXY" "$TARGET$path" >/dev/null || true
done

echo "[+] running active probe against every row with query params"
"$CLI" probe-all 200 100 >/dev/null

echo "[+] waiting for probes to land"
# The probes are async on the server. Poll the snapshot until the count
# stabilises for two consecutive reads.
prev=0; same=0
for _ in $(seq 1 60); do
    cur=$(curl -sS "$API/api/snapshot" | jq -r '.findingsCount')
    if [[ "$cur" == "$prev" ]]; then
        ((same++)) || true
        [[ $same -ge 2 ]] && break
    else
        same=0
    fi
    prev=$cur
    sleep 2
done

echo "[+] exporting SARIF to $SARIF_OUT"
"$CLI" export sarif > "$SARIF_OUT"

HIGH=$(jq '[.runs[0].results[] | select(.level=="error")] | length' "$SARIF_OUT")
echo "[+] sarif: $(jq '.runs[0].results | length' "$SARIF_OUT") finding(s), $HIGH high"

if [[ $HIGH -gt 0 ]]; then
    echo "[FAIL] $HIGH high-severity finding(s) — see $SARIF_OUT"
    jq -r '.runs[0].results[] | select(.level=="error") | "  - \(.ruleId) :: \(.message.text | split("\n") | first)"' "$SARIF_OUT"
    exit 1
fi

echo "[OK] no high-severity findings"
