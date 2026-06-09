# Nullock

**FOSS web security toolkit.** MITM proxy + repeater + intruder + scanner + OAST + native gRPC/GraphQL/CBOR/SAML decoders + AI-assisted triage. Self-host-first. No telemetry. MIT licensed.

[Download](https://github.com/Bikebrainz/Nullock/releases/latest) · [Docs](https://bikebrainz.github.io/Nullock/docs/getting-started.html) · [Marketplace](https://bikebrainz.github.io/Nullock/marketplace/) · [Discord (TBD)](https://github.com/Bikebrainz/Nullock/discussions)

---

## What's in the box

```
Proxy             HTTP/1.1 + HTTP/2 + WebSocket, all with native frame visibility
Repeater          Multi-tab, send-to-Repeater from history, edit-and-resend
Intruder          Sniper mode, custom payloads, rate-limit-aware
Scanner           Passive (10 finding types) + active (XSS/SQLi/SSRF/SSTI/cmd-i/CRLF/traversal/cloud-metadata)
Intercept         Pause/forward/drop with queue management
OAST              In-process HTTP callback sink for blind-bug detection
Session rules     Auto-extract CSRF/JWT/nonces and re-inject (Burp macros equivalent)
Crawler           BFS link-follower, scope-gated, feeds scanner
Port scan + recon CIDR sweeps, DNS, WHOIS, cert transparency, wordlist enum
Extensions        JS plugin API, onRequest/onResponse hooks, marketplace catalog
Decoders          JWT (with security annotations), GraphQL, gRPC, CBOR, SAML, base64, hex, JSON
SQLite history    200k+ row engagements stay snappy
AI triage         Local Ollama for impact/fix/FP-likelihood per finding
Scriptable CLI    25+ subcommands -- drive every panel from your shell
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
| Active scanner | ✓ | — | ✓ | — |
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
   │  ActiveProbe    6 vuln classes                 │         │  9 tabs:      │
   │  PortScanner    CIDR + banner grab             │         │  proxy / scope│
   │  ReconEngine    DNS / crt.sh / wordlist        │         │  rules / find │
   │  Repeater       multi-tab                      │         │  scans / recon│
   │  Intruder       sniper + rate-limit-aware      │         │  stats / repr │
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
- [ ] v3: HTTP/3/QUIC, hosted OAST tier, team workspaces, Apple notarization, code signing
- [ ] v4: SOC2, enterprise SSO, Web Security Academy clone (50+ labs)

## Contributing

PRs welcome. Read [`SECURITY.md`](SECURITY.md) for the threat model first if you're touching the proxy or control server.

## License

MIT. See [`LICENSE.md`](LICENSE.md).

Privacy + acceptable use: [`PRIVACY.md`](PRIVACY.md), [`TERMS.md`](TERMS.md).
