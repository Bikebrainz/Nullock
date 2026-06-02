#!/usr/bin/env bash
# Recon a domain (DNS + small wordlist), then fire a curl through the
# proxy at every found subdomain that resolves. Captured rows then get
# active-probed.
#
# Usage:  recon-to-probe.sh <domain>
#
# Requires curl + jq + a running Nullock with proxy on 8080.

set -euo pipefail

DOMAIN=${1:?"usage: $0 <domain>"}
CLI="$(dirname "$0")/../bin/nullock"
API=${NULLOCK_API:-http://127.0.0.1:17777}
PROXY=${HTTP_PROXY:-http://127.0.0.1:8080}

echo "[+] recon $DOMAIN"
RECON=$("$CLI" recon "$DOMAIN")
echo "$RECON" | jq '.dns'

# Pull resolved subdomain names. Skip ones that didn't resolve.
SUBS=$(echo "$RECON" | jq -r '[.subdomains[] | select(.ips | length > 0) | .name] | .[]')
N=$(echo "$SUBS" | grep -c . || true)
echo "[+] $N resolved subdomain(s); poking each through the proxy"

while IFS= read -r host; do
    [[ -z $host ]] && continue
    # Try https first, fall back to http. Don't fail the whole script if
    # one host is dead.
    curl -ks --max-time 8 --proxy "$PROXY" "https://$host/" >/dev/null || \
        curl -s  --max-time 8 --proxy "$PROXY" "http://$host/"  >/dev/null || true
done <<< "$SUBS"

echo "[+] firing active probe against every captured row with query params"
"$CLI" probe-all 200 50 >/dev/null

sleep 6
echo "[+] findings:"
"$CLI" findings high
"$CLI" findings medium
echo "[OK] done"
