#!/usr/bin/env bash
# Regenerate the marketplace manifest's integrity fields from the actual files,
# and mirror it to the published copy under docs/.
#
# WHY THIS EXISTS. The manifest's sha256 is the only thing standing between a
# compromised CDN and arbitrary code running inside a user's proxy. A hash that
# is edited by hand drifts the moment someone touches an extension, and a
# DRIFTED hash is worse than no hash: every install fails, and the obvious fix a
# frustrated maintainer reaches for is to stop verifying. So the hashes are
# generated, never typed, and CI re-runs this in --check mode to prove the
# committed manifest still matches the committed .js files.
#
#   scripts/marketplace_sync.sh            rewrite the manifests
#   scripts/marketplace_sync.sh --check    exit 1 if they are out of date
#
# The `permissions` field is likewise derived from each script's own
# `// nullock:permissions` directive rather than hand-maintained, so the catalog
# cannot advertise something different from what the engine will enforce. (The
# app still re-derives this from the downloaded bytes at install time and does
# not trust the catalog -- this only keeps the published copy honest.)

set -euo pipefail

cd "$(dirname "$0")/.."

SRC="extensions/marketplace.json"
MIRROR="docs/marketplace/marketplace.json"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

command -v python3 >/dev/null 2>&1 && PY=python3 || PY=python

"$PY" - "$SRC" "$CHECK" <<'PYEOF'
import hashlib, json, io, os, re, sys

src, check = sys.argv[1], sys.argv[2] == "1"

with io.open(src, encoding="utf-8") as f:
    doc = json.load(f)

# Same grammar ExtensionPerms::parsePermissions() implements. Kept deliberately
# simple: if this and the C++ ever disagree, the C++ wins at install time, and
# the mismatch shows up as an "undeclared permission" warning to the user rather
# than as a silent over-grant.
PERM = re.compile(
    r"^[ \t]*//[ \t]*(?:@)?nullock[:-]permissions[ \t]+(.+)$",
    re.IGNORECASE | re.MULTILINE)

ALIAS = {
    "onrequest": "modify-requests",
    "modify-request": "modify-requests",
    "onresponse-mutate": "modify-responses",
    "modify-response": "modify-responses",
}

changed = []
for ext in doc.get("extensions", []):
    ident = ext.get("id", "")
    path = os.path.join("extensions", ident + ".js")
    if not os.path.exists(path):
        sys.stderr.write("MISSING: %s (referenced by id %r)\n" % (path, ident))
        sys.exit(2)

    raw = io.open(path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()

    text = raw.decode("utf-8", "replace")[:65536]
    perms = []
    for m in PERM.finditer(text):
        for tok in re.split(r"[,\s]+", m.group(1).strip()):
            if not tok:
                continue
            tok = tok.strip().lower()
            tok = ALIAS.get(tok, tok)
            if tok in ("modify-requests", "modify-responses") and tok not in perms:
                perms.append(tok)
    perms.sort()

    if ext.get("sha256") != digest:
        changed.append("%s sha256 %s -> %s" % (ident, ext.get("sha256", "(none)")[:12], digest[:12]))
        ext["sha256"] = digest
    if ext.get("permissions", []) != perms:
        changed.append("%s permissions %r -> %r" % (ident, ext.get("permissions", []), perms))
        ext["permissions"] = perms

    # Keep key order stable and predictable so the diff of this file stays
    # readable and a real change is never buried in a reordering.
    order = ["id", "name", "summary", "version", "author", "categories",
             "url", "sha256", "permissions", "hooks", "updated", "config"]
    for k in order:
        if k in ext:
            ext[k] = ext.pop(k)

if check:
    if changed:
        sys.stderr.write("marketplace manifest is STALE:\n  " + "\n  ".join(changed) + "\n")
        sys.stderr.write("run scripts/marketplace_sync.sh to regenerate\n")
        sys.exit(1)
    print("marketplace manifest is in sync")
    sys.exit(0)

with io.open(src, "w", encoding="utf-8", newline="\n") as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
    f.write("\n")

print("updated %s" % src)
for c in changed:
    print("  " + c)
PYEOF

if [ "$CHECK" = "0" ]; then
    mkdir -p "$(dirname "$MIRROR")"
    cp "$SRC" "$MIRROR"
    echo "mirrored -> $MIRROR"
else
    if ! diff -q "$SRC" "$MIRROR" >/dev/null 2>&1; then
        echo "ERROR: $MIRROR differs from $SRC -- run scripts/marketplace_sync.sh" >&2
        exit 1
    fi
    echo "mirror is in sync"
fi
