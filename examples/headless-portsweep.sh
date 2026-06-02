#!/usr/bin/env bash
# Sweep a CIDR or host list with the discovery preset and dump open hosts
# as nmap XML.
#
# Usage:  headless-portsweep.sh <cidr-or-hostlist> [output-xml]
# Examples:
#   ./headless-portsweep.sh 192.168.1.0/24 lan-sweep.xml
#   ./headless-portsweep.sh "1.1.1.1,8.8.8.8,9.9.9.9"
#
# Requires curl + jq, and a Nullock instance reachable at $NULLOCK_API.

set -euo pipefail

TARGET=${1:?"usage: $0 <cidr-or-hostlist> [output.xml]"}
OUT=${2:-nullock-sweep.xml}
CLI="$(dirname "$0")/../bin/nullock"
API=${NULLOCK_API:-http://127.0.0.1:17777}

echo "[+] scanning $TARGET (discovery preset)"
"$CLI" scan "$TARGET" discovery > /tmp/nullock-scan-open.json

echo "[+] open hosts:"
jq -r '.[] | "\(.host)\t\(.port)\t\(.service // "?")"' /tmp/nullock-scan-open.json \
    | sort -u

echo "[+] exporting nmap XML to $OUT"
curl -sS "$API/api/export/nmap-xml" > "$OUT"
wc -l "$OUT"
echo "[OK] done"
