# Nullock

**FOSS web security toolkit.** MITM proxy + repeater + intruder + scanner + OAST + native gRPC/GraphQL/CBOR/SAML decoders + AI-assisted triage. Self-host-first. No telemetry. MIT licensed.

[Download](https://github.com/Bikebrainz/Nullock/releases/latest) · [Docs](https://bikebrainz.github.io/Nullock/docs/getting-started.html) · [Marketplace](https://bikebrainz.github.io/Nullock/marketplace/) · [Discord (TBD)](https://github.com/Bikebrainz/Nullock/discussions)

---

## What's in the box

```
Proxy             HTTP/1.1 + HTTP/2 + WebSocket, native frame visibility, intercept queue
Repeater          Multi-tab, send-from-history, edit-and-resend, request chains
Intruder          Sniper / Battering Ram / Pitchfork / Cluster Bomb, custom payloads, rate-limit-aware
Passive scanner   Header/cookie/secret/info-leak findings, every one CWE/OWASP/CVSS-enriched
Active scanner    SQLi (error + blind/time), NoSQLi, LDAP + XPath injection, XXE, SSTI, OS cmd-i,
                  CRLF, path traversal, reflected XSS, IDOR, verb tampering, open redirect, CORS,
                  mass assignment, SSRF (cloud-metadata/file/internal, fetch-proven), insecure
                  deserialization (Java/PHP/Python/Ruby/.NET), cross-site WebSocket hijacking,
                  host-header injection, server-side prototype pollution, security-header/CSP audit,
                  web cache poisoning + deception, dangerous HTTP methods, sensitive-file exposure,
                  HTTP request smuggling, race conditions
Version -> CVE    Active fingerprint + service-banner version detection correlated to a curated CVE
                  database (WordPress/Drupal/Joomla/Confluence/Jira/Jenkins/Grafana/Elasticsearch/Kibana/Tomcat/PHP/...),
                  with multi-branch ranges so patched builds aren't flagged; runtime NVD feed overlay
Recon             Port/CIDR sweeps, DNS, WHOIS, cert transparency, wordlist enum, robots/sitemap,
                  WAF/CDN detection, subdomain-takeover fingerprints, HTTP/3 (Alt-Svc) readiness,
                  scope-gated BFS crawler
TLS audit         Certificate + protocol/cipher inspection (expired/self-signed/weak-key/legacy proto)
OAST              In-process HTTP + DNS callback sinks for out-of-band confirmation -- one blast
                  confirms blind SSRF, RCE (OS command injection), XXE, and Log4Shell (jndi/DNS);
                  plus a deployable standalone server (nullock-oast) for a public / hosted tier
Orchestration     One-call host assessment + recon->vuln pipeline (point-at-host -> findings)
Reporting         Markdown / styled HTML / JSON reports, posture grade, OWASP + compliance coverage,
                  asset inventory, findings baseline/diff for repeat engagements
Session rules     Auto-extract CSRF/JWT/nonces and re-inject (Burp macros equivalent)
Sequencer         Statistical randomness analysis of session tokens (Burp Sequencer equivalent)
Extensions        JS plugin API, onRequest/onResponse hooks, marketplace catalog
Decoders          JWT (security-annotated) + forge, GraphQL, gRPC, CBOR, SAML, base64, hex, JSON
Exports           SARIF, CycloneDX SBOM, nmap-XML, Postman, OpenAPI, HAR
SQLite history    200k+ row engagements stay snappy
AI triage         Local Ollama for impact/fix/FP-likelihood per finding
Scriptable CLI    Drive every panel from your shell
Teaching labs     50 intentionally-vulnerable apps, each mapped to a Nullock probe (labs/)
Browser extension Chrome MV3 companion -- one-click proxy + CA install path
```

## 30 seconds to first capture

### Windows
```cmd
:: download Nullock-1.0.0-win64.exe from Releases, run it
NullockApp --proxy-port=8080 --control-port=17777
```

### Linux
```sh
# Debian/Ubuntu
sudo apt install ./Nullock-1.0.0-Linux.deb
# Fedora/RHEL
sudo dnf install ./Nullock-1.0.0-Linux.rpm
# any distro
chmod +x Nullock-x86_64.AppImage && ./Nullock-x86_64.AppImage
```

### macOS
```sh
# download Nullock-1.0.0-Darwin.dmg, right-click -> Open the first time
```

Then in another terminal:
```sh
nullock status
nullock history 10
nullock scan target.example top100
nullock oast mint            # for blind-bug testing
nullock crawler start https://target.example
```

Full quickstart: <https://bikebrainz.github.io/Nullock/docs/getting-started.html>

## Why Nullock vs Burp / ZAP / mitmproxy

| | Nullock | Burp Community | Burp Pro | mitmproxy |
|---|---|---|---|---|
| Price | Free | Free | $475/yr | Free |
| Active scanner | ✓ (20+ classes) | — | ✓ | — |
| Version→CVE correlation | built-in | — | addon | — |
| Reporting (HTML/SARIF/SBOM) | ✓ | — | partial | — |
| OAST (Collaborator) | in-process | — | hosted | — |
| Session handling rules | ✓ | — | ✓ | — |
| CLI control of every panel | ✓ | — | jython | ✓ |
| SQLite history at 200k+ | ✓ | — | partial | — |
| AI triage | local Ollama | — | — | — |
| Native gRPC/GraphQL | ✓ | — | paid addons | — |
| HTTP/3 / QUIC | — | — | — | — |
| Brand recognition | v1 | huge | huge | large |

Full honest comparison: <https://bikebrainz.github.io/Nullock/#compare>

## Architecture

```
   ┌──────────── headless backend (Qt6 / C++20) ────┐         ┌─── browser ───┐
   │                                                │         │               │
   │  ProxyServer    HTTP/1.1 + h2 + WS             │         │  React UI     │
   │  CertAuthority  forged leaf certs via OpenSSL  │         │  ui-v2/*.jsx  │
   │  Intercept      pause / forward / drop         │         │  Babel        │
   │  MatchReplace   regex per section              │ <─────> │  in-browser   │
   │  PassiveScanner 10 finding kinds               │  HTTP   │               │
   │  ActiveProbe    20+ vuln classes               │         │  9 tabs:      │
   │  PortScanner    CIDR + banner grab             │         │  proxy / scope│
   │  ReconEngine    DNS / crt.sh / wordlist        │         │  rules / find │
   │  Repeater       multi-tab                      │         │  scans / recon│
   │  Intruder       4 modes + rate-limit-aware     │         │  stats / repr │
   │  OastServer     in-process callback sink       │         │  intercept    │
   │  Crawler        BFS link-follower              │         │  intruder     │
   │  SessionRules   extract/inject variables       │         │  settings     │
   │  HistoryIndex   SQLite metadata + full rows    │         │               │
   │  Extensions     JS in QJSEngine                │         │               │
   │  UpdateChecker  GitHub Releases poll           │         │               │
   │  CrashReporter  local-only crash logs          │         │               │
   │                                                │         │               │
   │  ControlServer  REST API + static UI host      │         │               │
   │     127.0.0.1:17777 (CSRF + Host pinned)       │         │               │
   └────────────────────────────────────────────────┘         └───────────────┘
```

## Build from source

Requirements: CMake 3.24+, Qt 6.7+, C++20 (MSVC 2022 / GCC 13+ / Clang 16+), libnghttp2, OpenSSL.

```sh
git clone https://github.com/Bikebrainz/Nullock
cd Nullock
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

To produce installer artifacts:
```sh
cd build && cpack
# outputs Nullock-1.0.0-<platform>.<ext>
```

Per-platform packaging notes: [`packaging/README.md`](packaging/README.md).

## Security model

Nullock by design handles untrusted bytes. The threat model + 23 explicit attack surfaces we defend against are documented in [`SECURITY.md`](SECURITY.md). We aim to respond to security reports within 72 hours; full SLA in the docs.

To report a vulnerability: [`github.com/Bikebrainz/Nullock/security/advisories`](https://github.com/Bikebrainz/Nullock/security/advisories).

## Roadmap

- [x] v1: proxy, repeater, intruder, scanner, OAST, extensions API, SQLite history
- [x] v1.1: TLS fingerprint shaping, browser extension, 8 labs, marketplace catalog
- [x] v2: native h2/gRPC/GraphQL/CBOR/SAML, reverse OpenAPI, AI triage, cookie tomography, 12 labs, CI
- [x] v2-ship: installers, marketing site, docs portal, crash reporter, update checker, project templates, report builder
- [ ] v3:
  - [x] HTTP/3 detection — Alt-Svc `h3` readiness probe (`nullock http3`); full QUIC client transport still pending a QUIC dependency
  - [x] code signing + Apple notarization — release CI wired (activates on cert secrets); see [`RELEASE_SIGNING.md`](RELEASE_SIGNING.md)
  - [x] hosted OAST tier — deployable `nullock-oast` server + Docker + [`DEPLOY_OAST.md`](DEPLOY_OAST.md) (you supply the host + DNS)
  - [ ] team workspaces — **Phase-1 findings-sync server shipped** (`nullock-workspace`, [`DEPLOY_WORKSPACE.md`](DEPLOY_WORKSPACE.md)); design + later phases: [`design/team-workspaces.md`](design/team-workspaces.md)
- [ ] v4:
  - [x] Web Security Academy clone — **50/50 labs** under [`labs/`](labs/)
  - [ ] enterprise SSO — design: [`design/enterprise-sso.md`](design/enterprise-sso.md)
  - [ ] SOC2 (organizational/audit process)

## Contributing

PRs welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for build/test setup and
the patterns for adding a scanner, lab, or extension, and
[`INSTALL.md`](INSTALL.md) for per-platform install/build. Read
[`SECURITY.md`](SECURITY.md) for the threat model first if you're touching the
proxy or control server. Changes are recorded in [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT. See [`LICENSE.md`](LICENSE.md).

Privacy + acceptable use: [`PRIVACY.md`](PRIVACY.md), [`TERMS.md`](TERMS.md).
