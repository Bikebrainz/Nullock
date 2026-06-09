# Privacy Policy

_Last updated: 2026-06-09_

Nullock is a local-first security tool. The short version of this
policy: **Nullock does not collect, transmit, or store your data on
any server we control unless you explicitly opt into a hosted feature.**

The long version is below.

## What runs locally vs what touches the network

| Component | Network reach | Default |
|---|---|---|
| Proxy server | Only between your browser and your target | On |
| Control HTTP server | Bound to `127.0.0.1` only | On |
| HTTP history | Stored only in your project directory | On |
| OAST callback sink | Bound locally; receives only what targets you point at it | On |
| Update check | One HTTPS GET to `api.github.com` at startup | On (disable with `--no-update-check`) |
| AI triage (Ollama) | Goes to whatever Ollama URL you configure, default `127.0.0.1:11434` | Opt-in (you click "Triage") |
| Crash reporter | Writes report to your filesystem; upload is opt-in only | Opt-in |
| Extensions marketplace | Browses static GitHub Pages site | Opt-in (manual visit) |

That's it. We don't operate any backend services. There is no
"Nullock account." There is no telemetry by default.

## Update check details

At startup, Nullock makes one HTTPS request to
`https://api.github.com/repos/Bikebrainz/Nullock/releases/latest`. The
purpose is to surface "Update X.Y.Z available" in the UI. **What
GitHub sees**: the request's source IP, a `User-Agent:
nullock-update-check/1.0` header, and standard HTTPS metadata.
**What we see**: nothing. The request goes to GitHub, not to us.

Disable: launch with `--no-update-check`, or set environment variable
`NULLOCK_NO_UPDATE=1`.

## Crash reporter details

If Nullock crashes, we write a minimal report (stack trace, OS
version, project name redacted to its hash) to:

- Windows: `%LOCALAPPDATA%\Nullock\crashes\`
- macOS: `~/Library/Application Support/Nullock/crashes/`
- Linux: `~/.local/share/Nullock/crashes/`

We do NOT automatically upload these. The crash dialog asks you to
review the report and gives you a copy-paste button to file a GitHub
issue. If we ever build a backend reporter, it will be opt-in with
a separate, clearer prompt.

## Captured traffic

Nullock is a MITM proxy. By design, it sees every byte of HTTP/HTTPS
traffic you route through it. That data is:

- Stored only in your project directory (`%APPDATA%/Nullock/projects/`
  on Windows, `~/.local/share/Nullock/projects/` on Linux,
  `~/Library/Application Support/Nullock/projects/` on macOS)
- Written to `history.ndjson` and `history-index.sqlite`
- Persisted to disk until you delete the project

We never transmit captured traffic anywhere. Exports (HAR / Postman /
SARIF / OpenAPI) are user-initiated and write to a file path you
choose; they don't go to us.

## Extensions

If you install a JavaScript extension, that extension runs inside
Nullock's QJSEngine. Extensions have the same access to captured
traffic that Nullock itself does. **Only install extensions whose
code you've reviewed.** A malicious extension can exfiltrate
everything you've captured.

The built-in extensions (`aws_sigv4.js`, `identity_rotate.js`) are
source-readable in the repo. The marketplace catalog lists their
SHA256 hashes; verify before installing.

## Children

Nullock is a security testing tool. It is not designed for or
directed at children under 13.

## Changes to this policy

We'll update the date at the top and post a changelog in
`CHANGELOG.md`. For substantive changes (anything that adds a new
network call or storage location), we'll bump the major version
number.

## Contact

Open an issue at https://github.com/Bikebrainz/Nullock/issues with
the `privacy` label.
