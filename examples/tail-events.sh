#!/usr/bin/env bash
# Tail the --ndjson event stream from a Nullock process and pretty-print
# interesting events. Run as a sidecar while you proxy a target manually.
#
# Usage:  tail-events.sh < /dev/null < <(NullockApp --headless --ndjson 2>/dev/null)
# Or just pipe an existing log:
#   cat /tmp/nullock.log | tail-events.sh
#
# Colour codes are ANSI; pipe through `cat` to strip.

set -euo pipefail

# Colour helpers (degrade gracefully if not a tty).
if [[ -t 1 ]]; then
    R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; M=$'\e[35m'
    C=$'\e[36m'; W=$'\e[37m'; D=$'\e[2m'; Z=$'\e[0m'
else
    R= G= Y= B= M= C= W= D= Z=
fi

while IFS= read -r line; do
    # Skip blank / non-JSON lines.
    [[ -z $line || ${line:0:1} != "{" ]] && continue
    event=$(echo "$line" | jq -r '.event // "?"' 2>/dev/null) || continue
    case $event in
        ready)
            echo "${G}● READY${Z}  $(echo "$line" | jq -c '{proxy:.proxyPort, control:.controlPort, project}')"
            ;;
        response)
            method=$(echo "$line" | jq -r '.method')
            host=$(echo "$line"   | jq -r '.host')
            path=$(echo "$line"   | jq -r '.path')
            status=$(echo "$line" | jq -r '.status')
            sz=$(echo "$line"     | jq -r '.bytes')
            color=$W
            [[ $status -ge 400 ]] && color=$R
            [[ $status -ge 300 && $status -lt 400 ]] && color=$Y
            [[ $status -ge 200 && $status -lt 300 ]] && color=$G
            printf "${D}→${Z} %-6s %s ${color}%3d${Z} ${D}%5sB${Z} %s%s\n" \
                "$method" "${host:0:20}" "$status" "$sz" "${path:0:60}"
            ;;
        finding)
            sev=$(echo "$line"     | jq -r '.severity')
            kind=$(echo "$line"    | jq -r '.kind')
            summary=$(echo "$line" | jq -r '.summary')
            url=$(echo "$line"     | jq -r '.url')
            color=$D
            [[ $sev == high   ]] && color=$R
            [[ $sev == medium ]] && color=$Y
            [[ $sev == low    ]] && color=$M
            printf "${color}! %-6s${Z} %-22s %s ${D}%s${Z}\n" \
                "$sev" "$kind" "$summary" "${url:0:60}"
            ;;
        *)
            echo "${D}?${Z} $line"
            ;;
    esac
done
