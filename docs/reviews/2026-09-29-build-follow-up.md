# September 29 build follow-up

Owner: Bikebrainz. This is the next-work checklist from the September 29 build
and verification pass. The [capability register](../roadmap/parity.json) remains
the full roadmap; this list prioritizes gaps reproduced or inspected during the
session. An unchecked item is not implemented.

## Changes from this build

| Change | Pull request | Status |
| --- | --- | --- |
| Effective security headers and strict TLS certificate compatibility | [#21](https://github.com/Bikebrainz/Nullock/pull/21) | Merged |
| Reflected-XSS media types and HTML boundaries; certificate-cache validation | [#22](https://github.com/Bikebrainz/Nullock/pull/22) | CI pending |
| Stable history IDs, asynchronous CLI send polling and Stop | [#25](https://github.com/Bikebrainz/Nullock/pull/25) | CI pending |
| Binary file/stdin requests and accurate tab response indicators | [#26](https://github.com/Bikebrainz/Nullock/pull/26) | CI pending |

Every implementation PR also updates the public changelog and roadmap. These
are development changes; they do not create a release or change the latest
published version. Certificate details from #23 and HTML-context details from
#24 were incorporated into #22.

## Next work, in priority order

### 1. Preserve response bytes through Repeater and Hex views

- [ ] Carry the original response bytes through the tab model, snapshot and
  per-tab history, with a separate decoded display representation.
- [ ] Make request Hex honor the request's actual UTF-8 or Latin-1 encoding.
- [ ] Make response Hex and binary export use the selected byte representation.

**Evidence:** a loopback response body `00 ff 80 41` becomes
`00 U+FFFD U+FFFD 41` in Repeater. `Repeater::send` converts the raw or decoded
body with `QString::fromUtf8`; `toHexDump` then UTF-8-encodes the display text.
The original bytes cannot be recovered from that string. A Latin-1 request can
send correctly while its Hex view shows different bytes.

**Done when:** all 256 byte values survive send, snapshot, history navigation,
project save/reload and export; Hex matches the fixture bytes. Compressed
responses distinguish original wire bytes from decoded body bytes. Include
empty bodies, invalid UTF-8, NULs and bodies larger than the preview limit.

### 2. Correct the remaining reflected-XSS HTML contexts

- [ ] Handle inert template contents and SVG/MathML parsing contexts.
- [ ] Expand the pinned-browser corpus before changing the parser or its grade.

**Evidence:** after the tag-boundary fixes, a 97-context browser comparison left
two mismatches for the marker `<nlk0a1b2c3d>`:

| HTML | Native marker classification | Chromium element present |
| --- | --- | --- |
| `<template><nlk0a1b2c3d>` | true | false |
| `<svg><title><nlk0a1b2c3d>` | false | true |

The browser result describes this marker's parsed context, not a proof that an
arbitrary script payload executes. Existing committed browser coverage lives in
`Tests/ui/xss_context_browser_test.cjs` and `xss_media_types_browser_test.cjs`.

**Done when:** the corpus covers nested templates, foreign-content integration
points, malformed nesting and script/raw-text states, with native results
matching the pinned browser. Keep XML execution, stored XSS and DOM XSS outside
the claim unless they receive their own implementation and verification.

### 3. Finish Repeater cancellation and native-window responsiveness

- [ ] Route the native QML Send button through the asynchronous send path and
  expose the same Stop state as the browser.
- [ ] Add cancellation to the socket-owning worker during connection, TLS,
  header and body waits.
- [ ] Keep concurrent sends from separate tabs as a separate design task.

**Evidence:** browser/API/CLI sends use `sendAsync`, but `Src/App/app.qml` still
calls `repeater.send()` directly. Current Stop sets an atomic flag checked
between responses and redirects; it does not interrupt a stalled socket.
`HttpClient` uses per-wait timeouts and a five-minute total read budget.

**Done when:** a controlled stalled connection, TLS handshake, header, fixed body
and chunked body can each be stopped promptly without cross-thread socket use.
The native window and browser remain responsive, no extra redirect is sent,
newer edits survive completion, and shutdown joins the worker cleanly.

### 4. Isolate OAST smoke fixtures and retain callback diagnostics

- [ ] Allocate separate HTTP and DNS sink ports for each smoke run, alongside
  the control/proxy ports, and verify startup on the requested listeners.
- [ ] Report callback failures from the mock instead of discarding exceptions.
- [ ] Check concurrent isolated runs and deliberate port conflicts.

**Evidence:** one integrated run passed 193 checks and missed three HTTP OAST
callbacks (SSRF, RCE and XXE); an isolated retry passed all 196. The cause of
that first failure is not established. `scripts/probe_smoke.sh` uses the default
OAST ports and suppresses exceptions from its HTTP callback mock.

**Done when:** concurrent runs do not share sinks or state, listener failures
produce a clear startup error, and callback diagnostics identify the failed
operation. Retain token-specific positive assertions and safe-target negative
controls; do not replace them with longer blind waits or automatic pass-on-retry.

### 5. Complete CA and certificate-cache lifecycle controls

- [ ] Revalidate expiry before returning an in-memory leaf.
- [ ] Define explicit CA/key validation and repair, including operator-visible
  trust changes.
- [ ] Add supported CA replacement and leaf-cache clearing/eviction controls.

**Evidence:** `CertAuthority::leafCertFor` returns an in-memory cache hit before
checking dates or the current CA. Disk-cache reuse after restart now checks the
CA signature, private key, DNS/IP SAN, dates and key identifiers. That fix does
not provide live CA replacement or repair of a broken root/key pair.

**Done when:** a controlled clock test refreshes an expired memory entry; valid
entries remain reusable; CA rotation cannot leave mixed old/new leaves; failures
are actionable without silently replacing a trusted root. Preserve owner-only
key permissions and test both OpenSSL and LibreSSL certificate generation.

### 6. Keep roadmap evidence specific and current

- [ ] Audit remaining entries whose gap text contradicts their current state or
  cites superseded line numbers and behavior.
- [ ] Give browser, CLI and native-window behavior separate descriptions when
  their implementations differ.
- [ ] Require a runnable regression or a precise source reference for each
  reconciliation; retain limitations instead of inferring full parity.

This pass corrects the obsolete Repeater scope-bypass claim: the shared
`HttpClient` checks outbound scope before connecting, including redirects, and
the API snapshots the request synchronously before scheduling its worker.
The 41-check outbound-scope regression passes. The native window's remaining
blocking Send behavior is a separate issue described above.

## Verification to carry forward

- Native suites: 102 passed on the combined XSS/certificate implementation.
- Public probe smoke: 196 passed on the isolated rerun; the earlier OAST misses
  remain recorded above.
- Strict TLS and runtime regressions: 64 checks with the native-window option;
  the later CLI build also passed 62 headless runtime checks.
- Pinned Chromium: 72 media-type and 95 HTML-context comparisons passed. An
  additional 1,238 generated media-type comparisons found no mismatches.
- CLI fixtures and real-app checks cover stable IDs, binary history bodies,
  multiple busy polls, refusal/timeouts, Stop, binary files/stdin, UTF-8, invalid
  base64 and fresh/completed/duplicated tab indicators.
- Website checks cover links, script integrity, generated-page freshness and
  desktop/mobile roadmap and changelog layout.

For each follow-up, update `CHANGELOG.md`, `docs/changelog.html` and the affected
roadmap evidence together. Run `python scripts/parity_report.py` after changing
the register, then `python scripts/check_web_assets.py` and the relevant
application/browser regression. Cross-platform CI must pass on the exact PR
head before an implementation merge.
