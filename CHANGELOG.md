# Changelog

All notable changes to Nullock are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/). Dates are when a build went out.

The public, prose version lives at
<https://bikebrainz.github.io/Nullock/changelog.html>; this file is the
developer-facing record.

## [Unreleased]

### Fixed
- **Sequencer bit-level tests no longer mislabel or silently skip corpora.** The
  token→bytes decoder had two silent-wrong paths: an odd-length hex corpus failed
  the even-length gate, fell through, and was decoded *and labelled* base64
  (wrong bytes and wrong scheme); and a single non-conforming token (a truncated
  sample, a JWT's `.`) set the whole corpus to "not applicable", so 999 good
  tokens got zero bit-level analysis because of one bad one. The decoder now
  picks the scheme by charset **majority**, treats a hex-charset corpus as hex at
  any length (odd tokens left-padded to preserve the half-byte), and **skips**
  non-conforming tokens instead of aborting — reporting the skipped count
  (`bitLevel.skipped`) rather than dropping it silently. A genuinely mixed corpus
  still reports not-applicable. Mutation-tested (both fixes discriminate). Closes
  roadmap #152. (Residual, documented: a base32/alphanumeric corpus is still
  labelled "base64" — the bytes are analysed correctly, only the label is
  imprecise; Qt ships no base32 decoder.)
- **Site nav no longer drops links on secondary pages.** The hand-written
  pages (about, pricing, changelog, license, privacy, security, support,
  terms, and the docs landing) carried a stale nav missing the
  Extensions/Labs/Roadmap links, so those tabs "disappeared" once you left the
  homepage. All pages now expose the full section set; a whole-site check
  confirms 0 broken links and every page reaches all five sections.

### Security
- **Locked seven previously-untested leaked-secret detectors.** The passive
  scanner ships ten `leaked-*` credential patterns but only three (AWS key, GitHub
  PAT, Stripe) had a regression test — so a regex regression could have silently
  stopped detecting GitHub App, Slack, SendGrid, Mapbox, Google API, PEM private
  key, or AWS secret leaks. Added positive detection cases for all seven (built at
  runtime from fragments so no literal secret sits in the repo); mutation-proven.
- **Locked all seven subdomain-takeover fingerprints.** The passive scanner
  raises a HIGH `takeover-*` finding when a 404/503 body carries a vendor
  "unclaimed resource" error page (S3 `NoSuchBucket`, Heroku *No such app*,
  GitHub Pages, Azure *Web Site not found*, Fastly *unknown domain*, Shopify
  *shop unavailable*, Tumblr), but none had a positive test — a broken needle
  would have silently stopped flagging takeovers. Added one positive case per
  vendor, a 503-branch lock, and a status-gate negative (the same needle in a
  `200` body must **not** fire); mutation-proven (s3 + tumblr needles).
- **Locked five previously-untested security-header checks.** The header auditor
  emitted `xcto-missing` (X-Content-Type-Options), `hsts-missing`, `csp-missing`,
  `csp-report-only`, and `csp-unsafe-eval`, but no test asserted them — a
  regression silently dropping any would have gone unnoticed. Added discriminating
  positive/negative cases (mutation-proven: disabling the `xcto`/`hsts` emits now
  fails the suite).
- **Cookie jar no longer replays a Secure cookie over cleartext (or refuses it on
  a non-standard TLS port).** The session/cookie-jar auto-inject gate decided a
  Secure cookie's transport by a port heuristic (`port == 443`) instead of the
  actual connection encryption. That both *leaked* a captured Secure cookie onto a
  cleartext request that happened to use port 443 and *refused* to inject it over a
  genuine TLS connection on a non-standard port (e.g. 8443). `HttpRequest` now
  carries a real `tls` flag (set on the MITM'd HTTPS paths), and
  `injectableOverTransport(cookie, tls)` gates a Secure cookie strictly on TLS —
  fail-closed (an unknown transport never injects a Secure cookie). Mutation-tested.
  Fixes roadmap #165.

- **Header-audit redirect follower is now same-origin-only.** It previously
  gated redirects on hostname alone, so it would follow an `https→http` scheme
  downgrade or a port change and re-emit the captured `Cookie`/`Authorization`
  to that origin — over cleartext on a downgrade — while binding the new
  origin's verdicts to the original URL. It now requires an exact
  scheme+host+port match before following and never carries credentials across
  an origin change (`isSameOriginRedirect`, mutation-tested). Fixes finding #1
  of the multi-agent `Src/Core/Networking` security review.
- **JWT probe no longer reports false signature/algorithm bypasses on
  cookie-auth endpoints.** It stripped secondary credentials only on the
  no-token calibration shot, so a forged-token shot kept a carried session
  `Cookie` — a cookie-authenticated endpoint that ignores the JWT stayed
  authorized, and the (no-token denied / forged allowed) differential was
  misreported as a real bypass. It now strips every non-target credential on
  BOTH shots, leaving the injected JWT as the sole credential; the test that
  pinned the old behaviour is corrected. Fixes finding #2 of the review.

### Added
- **Cookie jar now captures the `Domain` attribute + RFC 6265 domain-matching
  (foundation for domain-scoped injection, #194).** The cookie-jar parser was
  dropping the `Domain` attribute entirely (only path/expires/httponly/secure/
  samesite were handled), so a `Domain=.example.com` cookie could never be scoped.
  `Set-Cookie` parsing now records the domain (lowercased, a single leading `.`
  stripped, empty ⇒ host-only), and a pure `domainMatches` predicate implements
  RFC 6265 §5.1.3 with a proper label boundary (`evil-example.com` does not match
  `example.com`) and IP-literal handling (exact-only). Unit- and mutation-tested.
  This is the foundation for #194 — wiring domain-aware, deterministic multi-host
  injection (plus the §5.3 Domain-vs-origin check) into `injectInto` remains.
- **Intruder "Bit flipper" generator (Burp parity).** A new `bitflip` payload
  type (`IntruderGenerators::bitFlip`) walks each byte of the base and emits one
  payload per bit position (LSB→MSB) with that single bit XOR-flipped — the
  standard fuzz for off-by-one parsers, checksum/MAC validators, and encoding
  edges. Output order and rendering match Burp exactly (`"ab"` → the 16 variants
  `` `b,cb,eb,ib,qb,Ab,!b,áb, ac,a`,af,aj,ar,aB,a",aâ``). Bounded at `kMaxCount`;
  wired into `/api/intruder/generate` + `types()`. Unit- and mutation-tested.
  Closes roadmap #35.
- **Intruder "Character substitution" generator (Burp parity).** A new `charsub`
  payload type (`IntruderGenerators::charSub`) takes a list of items and a
  character-substitution map (e.g. `e→3`, `t→7`) and, for each item, emits every
  combination of applying-or-not each substitutable position — all 2^k
  permutations (`peter` + `{e:3,t:7}` → the 8 leetspeak variants). Enumerated
  as a binary counter (leftmost position = LSB) to match Burp's order exactly;
  bounded at `kMaxCount`. Wired into `/api/intruder/generate` + `types()`. Unit-
  and mutation-tested. Closes roadmap #28 (which the audit mis-labelled
  "Character substring"; Burp's actual payload type is Character substitution).
- **Sequencer positional test now explains length-tolerance (Burp "Ignore token
  length differences").** The per-position (cross-sample) analysis needs a
  dominant token width and previously reported a bare `applicable:false` when it
  couldn't run — indistinguishable from a too-small corpus. The `positional`
  result now always carries `modalWidth`, `atModalWidth`, and `offWidth` (tokens
  excluded for not matching the modal width), plus a `skipReason`
  (`length-variance` / `too-few-tokens` / `too-few-at-width` / `tokens-too-short`)
  when it's skipped. So a variable-length corpus is now clearly flagged as such,
  and when the test does run the count of excluded off-width tokens is surfaced
  rather than silently dropped. Same applicable/gating behaviour as before;
  mutation-tested. Closes roadmap #144.
- **Intruder "Case modification" generator (Burp parity).** A new `casemod`
  payload type (`IntruderGenerators::caseMod`) takes a list of items and, for each,
  emits one payload per selected case option in canonical order — the five Burp
  options: No change, lower, upper, `Propername` (first letter upper, rest lower),
  and `ProperName` (first letter upper, rest unchanged) — for case-variant
  username/wordlist fuzzing. The two Proper modes are distinct exactly as the
  PortSwigger docs specify; the leading letter is upper-cased by code point
  (non-BMP safe). Wired into `/api/intruder/generate` + `types()`. Unit- and
  mutation-tested (the Propername-vs-ProperName distinction is locked). Closes #29.
- **Intruder "Character blocks" generator (Burp parity).** A new `blocks` payload
  type (`IntruderGenerators::charBlocks`) repeats a base string by a multiplier
  from min to max stepping by a step — one payload per multiplier (`base × k`),
  e.g. `"A"` × 1..3 → `A, AA, AAA` — for buffer-boundary / length-limit fuzzing.
  It multiplies (whole-repeat) the base, not truncate-to-length (verified against
  the PortSwigger docs). Bounded in count and total chars, and refuses to build a
  block that would breach the cap, so a huge multiplier can't OOM. Wired into
  `/api/intruder/generate` + `types()`. Unit- and mutation-tested. Closes #32.
- **Intruder "Character frobber" generator (Burp parity).** A new `frobber`
  payload type (`IntruderGenerators::frob`) walks a base string one position at a
  time, emitting one payload per position that is the whole base with exactly that
  character's code point incremented by +1 (Burp's frobber) — for probing
  off-by-one parsers, checksum/signature validators, and encoding edge cases. It
  increments by code point (not UTF-16 unit) and keeps every result a valid
  Unicode scalar (a bump into the surrogate range skips to U+E000, past U+10FFFF
  wraps to 0), and is bounded in both count and total char volume so a huge base
  can't OOM. Unit- and mutation-tested. Closes roadmap #34.
- **Intruder "Null payloads" generator (Burp parity).** A new `null` payload type
  (`IntruderGenerators::nullPayloads`) emits N empty payloads, filling a position
  with nothing so the base request is re-sent unchanged N times — the standard way
  to probe rate limits, race conditions, or non-deterministic responses. Capped at
  `kMaxCount`; wired into `/api/intruder/generate` + advertised by `types()`.
  Unit- and mutation-tested. Closes roadmap #33.
- **Intruder payload-processing now offers Decode rules (Burp "Decode" parity).**
  The rule dropdown (`/api/intruder/rule-ops`) previously advertised only encode
  and hash transforms — decode was deliberately hidden ("payloads are authored,
  not received"), but real payload lists arrive pre-encoded (base64 wordlists,
  URL/hex-encoded fuzz strings) and Burp offers decode rules for exactly that.
  The decode inverse of each advertised reversible encode — `base64-decode`,
  `base64url-decode`, `url-decode`, `hex-decode`, `html-decode` — is now offered.
  The ops already executed (they delegate to the Transcode workbench) and fail
  safe: a decode of non-decodable input is a no-op, so a payload never vanishes.
  Round-trips are unit- and mutation-tested. Closes roadmap #40.
- **Sequencer now detects WRAPPED counters.** The sequential/counter detector
  previously required a token to be numeric end-to-end, so a real-world wrapped
  counter — `sess_1001`, `user-42`, `id_007` — was reported "not sequential"
  (a false negative Burp's encoding-agnostic low-entropy inference still caught).
  A shared non-numeric wrapper is now stripped before the counter tests, so
  prefixed/suffixed decimal & hex counters are flagged with their true step,
  while a bare stepped counter (`100,200,300`) keeps its real delta and random
  tokens don't become false counters — all mutation-tested. The recovered step
  (`sequential.delta`) is now also value-locked, not just its boolean. This plus
  the dedicated `looksSequential`/`looksMonotonic`/`delta` verdict (which Burp
  has no equivalent for) makes counter detection exceed Burp. Closes roadmap #153.
- **Sequencer sample-size + FIPS 140-2 guidance.** The token-analysis result now
  carries a `sampleGuidance` block that makes two thresholds explicit and
  machine-readable: a warning under the recommended ~100-token minimum (with a
  harder "not even estimable" floor below the deep-test threshold), and whether
  the decoded bit-stream reaches the 20,000-bit FIPS 140-2 power-up-test sample.
  Previously the confidence was only an implicit qualitative label with no FIPS
  dimension. Pure helper `Core::sampleSizeGuidance(tokens, decodedBits)`,
  unit- and mutation-tested (the 100-token, deep-test, and 20,000-bit
  boundaries each discriminate). Closes roadmap #186.
- **XML issue report (`GET /api/report/xml`).** Serializes the engagement's
  findings — the same corpus as `report/json` — into a Burp-style XML issue
  report (`<nullockReport>` → `<issue severity/confidence/cvss/fixed>` with
  `name/host/url/cwe/owasp/detail/remediation` elements) for CI systems, SIEM
  ingestion, and XSLT pipelines that consume XML rather than SARIF/JSON. The
  finding→XML pass is a pure, unit-tested helper
  (`ControlLogic::findingsJsonToXml`): every attacker-influenced value
  (host/url/summary) is `xmlAttrEscape`'d, so a summary carrying `</issue>` or
  `<` cannot break the document framing — mutation-tested to prove the escaping
  discriminates.
- **Nuclei-style template scanner.** Author detection templates (JSON) or feed
  real nuclei `.yaml` templates (including `|` literal / `>` folded block
  scalars with chomping, for multi-line request bodies): matchers (status / word
  / regex with and/or + negative, over body / header / all), regex extractors,
  and an active request
  template (method / path / headers / body with `{{BaseURL}}` / `{{payload}}`
  substitution + cluster / pitchfork payload expansion, all bounded). `POST
  /api/template/run` (`{template | yaml | templateId}`) fires the request(s),
  matches each response, and reports a finding per match — so hits feed the
  panel, the CI gate, and the baseline diff. A bundled starter library
  (`templates/detections/`) ships six detections (exposed `.git/config` /
  `.env` / `.DS_Store`, directory listing, missing security headers,
  server-version disclosure); `GET /api/template/list` enumerates them and
  `templateId` runs one by id (path-traversal-guarded).
- **CI security gate.** `GET /api/gate?fail-on=<sev>` returns a pass/fail
  verdict plus a process exit code from the current findings; the one-shot CLI
  `NullockApp --scan <url> --fail-on <sev>` runs the deep audit headless and
  exits `0` / `1` / `2` for direct use in a pipeline. A composite GitHub Action
  (`.github/actions/nullock-scan`) and a reference multi-stage `Dockerfile` wrap
  it.
- **Intruder parity.** Payload-processing rules, payload generators
  (numbers / brute / dates, hard-capped), Grep-Match / Grep-Extract result
  columns, a bounded concurrency + throttle request pool, and save / resume of
  an attack run.
- **Inspector.** `POST /api/inspect` returns a structured view of a raw HTTP
  request/response — parsed query / form / JSON body params, cookies, headers,
  `Set-Cookie` breakdown, and any JWT (decoded header + payload) found in a
  header or cookie.
- **Response-side interception.** The intercepting proxy now holds and lets the
  operator edit/forward/drop *responses*, not just requests.
- **Extension permission model.** JS extensions run in a sandboxed `QJSEngine`
  (no filesystem/network); rewriting traffic is now capability-gated and
  default-deny — an extension must declare `// nullock:permissions
  modify-requests` (or `modify-responses`) or it stays observe-only. Documented
  in `EXTENSIONS.md`.
- **Offline UI.** The web UI vendors React / Babel locally (`ui-v2/vendor/`) and
  drops its CDN dependency, so it runs fully air-gapped.
- **Transparent response decompression** (gzip / deflate) so inspection,
  matching, and reporting see the decoded body.
- **Bearer-token auth** on the control API, mandatory for any off-loopback bind.
- **Asset-dir resolution** via `--ui-dir` / `NULLOCK_UI_DIR` plus auto-detection
  of the install layout.

### Changed
- Passive and active findings carry an explicit `confidence`
  (confirmed / firm / tentative).

### Fixed
- Blind-tunnel (`CONNECT`) passthrough no longer drops the relayed connection.
- Installed and containerized binaries now locate `ui-v2` and the detection
  templates instead of relying on a dev-only relative path.

## [3.7.0] — 2026-07-05
The academy + platform-completion release: the full 50-lab Web Security Academy
clone, the OWASP injection family completed (LDAP / XPath / SSRF /
deserialization / active JWT / CSWSH / host-header / prototype-pollution), OAST
out-of-band auto-confirmation, and the deployable standalone **nullock-oast**
sink + **nullock-workspace** team findings-sync server (both Dockerized).

### Added
- **Web Security Academy clone — 50 labs.** `labs/01`…`labs/50`, each a
  single-file intentionally-vulnerable app mapped to a Nullock probe
  (XXE, CRLF, dangerous HTTP methods, verb tampering, cache poisoning,
  sensitive-file exposure, robots disclosure, predictable session tokens,
  web-cache deception, insecure cookie flags, missing security headers,
  SSRF-to-metadata, OAuth `redirect_uri`, credentials-in-URL, and more).
- **Version → CVE coverage** for Atlassian Confluence (incl. CVE-2023-22515,
  CVE-2023-22518, CVE-2023-22527, CVE-2022-26134) and Jira (CVE-2022-0540,
  CVE-2019-8449, CVE-2019-11581), Jenkins (CVE-2024-23897), Grafana
  (CVE-2021-43798), Apache (CVE-2021-41773/42013), nginx (CVE-2021-23017),
  jQuery, and Bootstrap — all multi-branch ranged so patched builds aren't
  false-flagged, all verified end-to-end.
- **`nullock scope`** — in/out scope management from the CLI
  (`/api/scope/in|out/add|remove`, notes, list).
- **`nullock recon`** now also queries certificate transparency (crt.sh).
- **CSRF PoC generator** — `/api/csrf/poc` + `nullock csrf-poc <row-id>`
  turns a captured request into an auto-submitting HTML PoC.
- **Copy as curl** — `/api/request/curl` + `nullock curl <row-id>`
  reproduces a captured request as a runnable curl command.
- **Multi-mode Intruder** — Sniper / Battering Ram / Pitchfork / Cluster Bomb
  (`/api/intruder/multi`, `nullock intruder multi`), wired through the GUI.
- **Server-side prototype pollution** — `/api/protopollution/test` +
  `nullock protopollution`, the benign json-spaces gadget proven with a
  four-step causal (mutate → observe → revert) check.
- **Host-header injection** — `/api/hostheader/test` + `nullock hostheader`,
  detecting reset/redirect poisoning via sentinel-host reflection into a URL.
- **LDAP injection** — `/api/ldapi/test` + `nullock ldapi`, error-based with
  safe-value corroboration; completes the OWASP injection family.
- **HTTP/3 readiness** — `/api/http3/detect` + `nullock http3`, Alt-Svc h3
  advertisement detection.
- **Version → CVE** for Elasticsearch, Kibana (CVE-2019-7609), and Apache
  Tomcat (Ghostcat, CVE-2020-1938).
- **nullock-oast** — a deployable standalone OAST callback sink (Docker +
  `DEPLOY_OAST.md`) for a public / hosted tier.
- **Release signing** — the release workflow code-signs Windows builds and
  codesigns + notarizes the macOS app when cert secrets are present
  (`RELEASE_SIGNING.md`).
- Permanent regression suites for the CVE database, the finding enricher, the
  request-export transforms, and the Intruder engine — five suites run in CI on
  every push, alongside `scripts/probe_smoke.sh` (active-probe regression
  against in-process mocks).
- **XPath injection** — `/api/xpathi/test` + `nullock xpathi`, error-based with
  safe-value corroboration (mirrors the LDAP probe).
- **SSRF** — `/api/ssrf/test` + `nullock ssrf`, a first-class **fetch-proven**
  probe (cloud metadata incl. decimal/hex IP-encoding denylist bypasses, AWS IMDS
  IAM two-step, `file://` reads, internal-service loopback banners). Confirmation
  requires a response-only signature that's absent from the baseline AND from a
  same-shape non-fetchable shaped-control URL, so reflection/WAF templates can't
  false-positive.
- **Active JWT attacks** — `/api/jwt/test` + `nullock jwt test <url> <token>`,
  the active complement to the offline `jwt` toolkit: it sends forged tokens to a
  live endpoint and confirms acceptance (alg:none + case/empty/absent variants,
  signature-not-verified, weak-HMAC-secret, and RS256->HS256 algorithm confusion
  when a public key is supplied). Sound via a no-token/valid/forgery
  calibration with a second-send re-confirm. (Burp does JWT testing only via a
  paid extension.)
- **Cross-site WebSocket hijacking (CSWSH)** — `/api/cswsh/test` + `nullock
  cswsh`, an active probe that sends a cross-origin WebSocket upgrade and
  confirms only on `101` + a valid `Sec-WebSocket-Accept` (RFC 6455), with a
  no-Origin control to tell an origin-validating endpoint from a non-WS one.
- **Insecure deserialization** — `/api/deser/test` + `nullock deser`, an active
  probe for Java/PHP/Python/Ruby/.NET. Uses a well-formed-vs-malformed
  differential (a real deserializer accepts a benign well-formed object and errors
  on a malformed one; a shape-keyed WAF errors on both) so it's sound where a
  naive error gate is not. Payloads are inert canaries that fail before any gadget.
- **Out-of-band confirmation via OAST.** `nullock oast blast` now sprays blind
  **SSRF**, **OS command injection (RCE)**, **XXE**, and **Log4Shell** payloads at
  a target; a callback to the in-process HTTP sink (or the DNS sink, for the
  jndi/DNS Log4Shell leg) auto-confirms the class via the correlator — a
  true-positive-by-construction confirmation no response echo can give.
- **Time-based blind SQLi** is now exercised in the deep-audit battery (opt-in,
  `nullock sqli <url> blind`) with differential-timing confirmation.
- **Content/directory discovery** — `/api/content/discover` + `nullock content`,
  a soft-404-calibrated wordlist sweep.
- **Subresource Integrity** passive check — flags cross-origin `<script>` without
  `integrity=` (supply-chain risk, CWE-353).
- **nullock-workspace** — a deployable standalone team-findings sync server
  (SQLite, bearer-key auth, identity-key merge) with `nullock workspace push|pull`
  CLI, completing team-workspaces Phase 1 (Docker + `DEPLOY_WORKSPACE.md`).
- Design docs for team workspaces and enterprise SSO (`design/`).

### Changed / Fixed
- **Release workflow startup failure fixed.** The optional signing steps had
  referenced the `secrets` context in a step `if:` (not permitted), which made
  GitHub reject the workflow at parse time on every push; they now no-op
  in-script when the secret is absent.
- **CVE database accuracy audit.** Web-verified every entry against
  NVD/vendor advisories; corrected ~11 entries (per-branch ranges that
  false-positived patched builds, wrong CVSS scores, mislabeled vulns) and
  removed 3 bogus/false-positive entries.
- **Finding enricher coverage.** ~53 of 97 emitted finding kinds were
  shipping with empty CWE/OWASP; added family-prefix fallbacks + a generic
  last-resort so every finding is enriched.
- **CI restored to green.** The Windows build had been failing at the Qt
  install step (`qtquickcontrols2` is not a Qt 6 aqt module); fixed, wired
  the regression suites into the pipeline, and re-synced the marketplace
  docs mirror.

## [3.6.0] — 2026-06-17
The platform release: a network scanning + reporting + recon suite.
Port-scan → findings bridge, recon → vuln pipeline (`nullock pipeline`),
WAF/CDN and robots/sitemap recon, a live CVE-feed overlay (`nullock cvefeed`),
and engagement reporting — HTML (A–F grade), JSON bundle, CycloneDX SBOM,
OWASP/compliance coverage, asset inventory, posture grade, baseline diff.
Each feature shipped with an adversarial review and a regression test.

## [3.5.0] — 2026-06-11
The active-testing climb: a full battery of injection, access-control, and
misconfiguration scanners (SQLi error + blind, NoSQLi, XXE, SSTI, OS cmd-i,
reflected XSS, CRLF, LFI/path-traversal, IDOR/BOLA, mass assignment, active
CORS, verb tampering, open redirect, web cache poisoning + deception,
header/CSP audit, secret scanning, request smuggling), plus identification
modules (service→CVE, TLS inspection, fingerprint, HTTP methods, subdomain
takeover, sensitive-file exposure) and **ScopeGuard** — one authorization
gate on every active test. HTTP-client correctness fixes throughout.

## [3.4.0] — 2026-06-11
Active testing & API-security: OAST auto-correlation + active OOB blast +
DNS sink, hidden-parameter mining, IDOR/BOLA, mass assignment, active CORS
exploitability. Each with adversarial review and false-positive guards.

## [3.3.0] — 2026-06-09
The "above the paid tools" release: CVE correlation, GraphQL attack probes,
DOM-XSS taint analysis, Repeater chains, and a JWT attack toolkit. Every
finding gained CWE / OWASP Top-10 2021 / CVSS v3.1 / one-line fix tags.

## [3.2.0] — 2026-06-02
Repeater side-by-side response diff with byte-level highlighting; streaming
scoped history export; SQLite write batching (~40% less capture overhead at
200k rows).

## [3.1.4] — 2026-05-18
Linux CA install fix under Wayland; match-and-replace empty-body fix;
`nullock vacuum` to compact history.

## [3.1.0] — 2026-04-29
JavaScript extension API (onRequest/onResponse hooks); glob scope syntax;
large-response streaming leak fix.

## [3.0.0] — 2026-03-11
First native desktop release: cross-platform Qt6/C++20 app over the same
control server the CLI drives, SQLite-backed history (200k+ rows), config
under `~/.nullock/`.

[Unreleased]: https://github.com/Bikebrainz/Nullock/compare/v3.7.0...Nullock
[3.7.0]: https://github.com/Bikebrainz/Nullock/compare/v3.6.0...v3.7.0
