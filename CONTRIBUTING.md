# Contributing to Nullock

Thanks for helping build a free toolkit that aims *above* Burp. This guide
covers building, testing, and the patterns for adding a scanner, a lab, or
an extension. If you're touching the proxy or control server, read
[`SECURITY.md`](SECURITY.md) (the threat model) first.

## Layout

```
Src/
  BackEnd/Control/control_server.cpp   # the :17777 HTTP control API (~110 /api/* routes)
  BackEnd/Proxy/                       # ProxyServer, CertAuthority, intercept, HttpRequest/Response
  Core/Networking/                     # the scanners/probes, CVE DB, fingerprint, enricher, recon, reporting
  Core/Storage/                        # SQLite history index, project store
  FrontEnd/GUI/                        # QML UI (QtQuick)
bin/nullock                            # bash CLI -- drives every /api endpoint
labs/                                  # 50 intentionally-vulnerable teaching apps
extensions/                            # JS plugin API + marketplace catalog
Tests/                                 # ctest regression suites
docs/                                  # GitHub Pages site
```

The control server is the seam: the GUI and the `bin/nullock` CLI are both
thin clients over `/api/*`. New capability = a backing module in
`Src/Core/Networking/` + a `/api/*` handler + a CLI subcommand + tests.

## Build (Windows)

Requires Visual Studio 2022 (MSVC), Qt 6.7.3 (`msvc2019_64`), and
nghttp2 (via vcpkg). **Use the CMake bundled with Visual Studio** —
`C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`.
A standalone CMake on PATH can mis-detect the compiler.

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
  -DNULLOCK_NGHTTP2_ROOT="C:/vcpkg/installed/x64-windows" ^
  -DCMAKE_PREFIX_PATH="C:/Qt/6.7.3/msvc2019_64"
cmake --build build --config Release --target NullockApp
```

Linux/macOS builds use the same CMake project with the platform Qt; see
[`INSTALL.md`](INSTALL.md).

## Run

```sh
# GUI
./build/Src/App/Release/NullockApp

# headless (no QML/browser) -- what CI + scripting use
./build/Src/App/Release/NullockApp --headless --control-port=17777 --proxy-port=8080 --project=/tmp/proj
```

## Test

Five regression suites run in CI on every push and locally via ctest:

```sh
cmake --build build --config Release ^
  --target scanner_regression_test cve_database_test finding_enricher_test request_export_test intruder_engine_test
ctest --test-dir build -C Release -R "scanner_regression|cve_database|finding_enricher|request_export|intruder_engine" --output-on-failure
```

- `scanner_regression` — every passive detector, positive + negative cases.
- `cve_database` — version→CVE correlation (vulnerable matches, patched
  builds don't, removed entries stay gone, CVSS values).
- `finding_enricher` — every emitted finding kind maps to a non-empty
  CWE/OWASP.
- `request_export` — CSRF-PoC + copy-as-curl transforms (escaping/structure).
- `intruder_engine` — the four attack-type combination generators + marker
  substitution.

`scripts/integration_smoke.ps1` is the whole-system check (import → CVE
feed → bridge → reports → ScopeGuard) against one headless instance — the
reliable go-to over the flakier `scripts/validate_v3.ps1`.

`scripts/probe_smoke.sh` is the deterministic **active-probe** regression: it
drives the headless server against reliable Python `http.server` mocks and
asserts each probe both fires on a vulnerable target and stays quiet on a safe
one (SQLi, reflected XSS, SSTI, OS command injection, XXE, open redirect, path
traversal, CORS, verb tampering, LDAP, XPath, server-side prototype pollution,
host-header injection, content discovery, HTTP/3 detection). Run it after
touching any probe -- and add a mock mode + assertion when you add one:

```sh
scripts/probe_smoke.sh            # auto-finds the Release build, or pass the exe path
```

## Adding a scanner / probe

1. Write `your_probe.{cpp,hpp}` in `Src/Core/Networking/` (add to that
   `CMakeLists.txt`). Confirm benignly — arithmetic canaries, OAST
   callbacks, content signatures — never weaponize. Build in
   false-positive guards (a control request, a balanced-payload check).
2. Add a `POST /api/your/probe` handler in `control_server.cpp`. If it
   sends traffic to a target, gate it through `ScopeGuard` (`blocksScope`)
   and add its path to `kActivePaths`.
3. Map every finding kind it emits to a CWE/OWASP/CVSS/fix in
   `finding_enricher.cpp` (the `finding_enricher` test will fail otherwise).
4. Add a `cmd_yourprobe` subcommand + dispatch + help line in `bin/nullock`.
5. Add a test (a regression case, or a `Tests/<name>` suite for pure logic).
6. If it's a teaching surface, add a matching `labs/NN-name/app.py`.

## Adding a lab

`labs/NN-name/app.py` — one self-contained Flask (or stdlib) app on port
`50NN`, with a module docstring walkthrough (the vulnerability, the
`nullock` steps to confirm it, and the upstream fix). Keep it under ~100
lines, Flask + `requests` only. Each lab should map to a Nullock probe.

## Commits & PRs

- One logical change per commit; explain *why* in the body.
- Run the test suites before opening a PR; CI must be green.
- Don't commit literal secrets in test fixtures — mint fakes at runtime via
  string concatenation (GitHub push protection scans for key shapes).

## Security issues

Don't open a public issue for a vulnerability in Nullock itself — follow the
disclosure process in [`SECURITY.md`](SECURITY.md).
