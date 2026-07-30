# Nullock Extensions Marketplace

A directory of Nullock extensions, browsable as a static page and installable
from inside the app (Settings -> Marketplace).

## How installing actually works

An extension is JavaScript that runs inside Nullock's proxy. That means it sees
every request and response your browser makes -- including session cookies and
bearer tokens on a live engagement. There is no sandbox downstream that makes a
bad install survivable, so the checks all happen *before* the file is written:

1. **The hash is pinned.** Every catalog entry carries a `sha256` of the exact
   script bytes. Nullock downloads, hashes, and refuses on any mismatch. An
   entry with a missing or malformed hash is not installable at all -- it fails
   closed, it does not fall back to "download it anyway". Compromising the CDN
   that serves the `.js` is therefore not enough on its own; an attacker also
   has to control the catalog.
2. **The transport is pinned.** `https` only, and only to
   `raw.githubusercontent.com` or `bikebrainz.github.io`. No plain HTTP, no
   other hosts, no non-443 ports, no redirect following, and no `user@host`
   URLs (which parse to a *different* host than they appear to).
3. **The filename is confined.** The on-disk name comes from the entry's `id`,
   which is remote data. Anything that could escape the extensions directory --
   separators, `..`, drive letters, UNC paths, `:` streams, Windows device names
   like `CON` -- is rejected rather than sanitised.
4. **Consent comes from the bytes, not from this file.** Nullock re-reads the
   `// nullock:permissions` directive out of the script it just downloaded and
   verified. If the script asks for a capability this catalog did not advertise,
   you are told at the confirm prompt. Anything that can *rewrite* traffic
   requires an explicit confirmation before it is written to disk.

Nothing auto-installs and nothing auto-updates. An "update available" badge is
information; the install only happens when you click it.

## Adding an extension

Open a PR against the root `extensions/marketplace.json`:

```json
{
  "id":         "<unique-slug>",
  "name":       "Human Readable Name",
  "summary":    "One sentence.",
  "version":    "0.1.0",
  "author":     "<your github handle>",
  "categories": ["<tag>", "<tag>"],
  "url":        "https://raw.githubusercontent.com/<your>/<repo>/<tag>/<path>.js",
  "sha256":     "<64 hex chars>",
  "permissions": ["modify-requests"],
  "hooks":      ["nullock.onRequest"],
  "config":     { "<key>": { "type": "string", "desc": "..." } }
}
```

**Do not fill in `sha256` or `permissions` by hand.** Run:

```sh
bash scripts/marketplace_sync.sh
```

It hashes the committed `.js`, reads each script's own permission directive,
rewrites both fields, and mirrors the manifest to `docs/marketplace/`. CI runs
the same script with `--check` and fails the build if the committed manifest has
drifted from the committed extensions -- a stale hash breaks every install, and
the tempting "fix" for that is to stop verifying.

Notes:

- `id` must be `[A-Za-z0-9._-]`, at most 64 characters, and becomes `<id>.js`
  on disk.
- Pin `url` to a **tag or commit SHA, never a branch**. A branch URL means the
  bytes can change after the hash was computed, and the next person to install
  gets an integrity failure.
- Declare permissions honestly. You gain nothing by omitting them -- Nullock
  reads the directive out of your script regardless, and an undeclared
  capability is surfaced to the user as a warning at install time.
- Add a `// nullock:version <semver>` line so Nullock can tell an installed copy
  from an update. Without it an installed extension is simply shown as
  installed and no update is offered.

## Deploy to GitHub Pages

1. Repo **Settings -> Pages**, pick **branch: Nullock** / **folder: /docs**.
2. The marketplace lands at `https://<owner>.github.io/Nullock/marketplace/`.
3. `scripts/marketplace_sync.sh` mirrors the root manifest into `docs/`, and CI
   verifies the two are identical.

## Deploy anywhere else

The page is static -- drop `docs/marketplace/` into any static host (Cloudflare
Pages, Netlify, S3 + CloudFront, a bare nginx server).

Note that Nullock's host allow-list is compiled in. If you self-host a fork's
catalog elsewhere, the app will refuse to fetch it until that host is added to
`trustedHosts()` in `Src/Core/Networking/marketplace_logic.cpp` -- deliberately,
since every entry there is a party that can hand the process code to execute.

## Local preview

```sh
python3 -m http.server -d docs/marketplace 8000
# then browse http://localhost:8000/
```
