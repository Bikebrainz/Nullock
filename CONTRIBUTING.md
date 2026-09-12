# Contributing to Nullock

Thanks for helping build a free toolkit that aims *above* Burp. This guide
covers building, testing, and the patterns for adding a scanner, a lab, or
an extension. If you're touching the proxy or control server, read
[`SECURITY.md`](SECURITY.md) (the threat model) first.

## Layout

```
Src/
  App/app.cpp                          # main(): builds and wires every object, owns shutdown order
  BackEnd/Control/control_server.cpp   # the :17777 HTTP control API (~110 /api/* routes)
  BackEnd/Proxy/                       # ProxyServer, CertAuthority, intercept, HttpRequest/Response
  Core/Networking/                     # the scanners/probes, CVE DB, fingerprint, enricher, recon, reporting
  Core/APIs/                           # JS extensions API + sandbox, OAST server/correlator
  Core/Storage/                        # SQLite history index, project store
  Core/Utils/                          # crash reporter
  Tools/                               # standalone binaries: nullock-oast, nullock-workspace
  FrontEnd/GUI/                        # native history models and theme manager
  FrontEnd/Resources/                  # bundled native resources
bin/nullock                            # bash CLI -- drives every /api endpoint
labs/                                  # intentionally-vulnerable teaching apps
extensions/                            # JS plugin API + marketplace catalog
Tests/                                 # ctest regression suites
docs/                                  # documentation index + GitHub Pages site
  guides/                              # installation, usage, deployment, release guides
  design/                              # architecture and feature designs
  reviews/                             # dated engineering reviews
ui-v2/                                 # browser application and vendored runtime
packaging/                             # installer and container support
scripts/                               # maintenance, generation, and regression tools
browser-ext/                           # companion browser extension
examples/                              # CLI workflow examples
templates/                             # detection rules and project presets
```

Application wiring and shutdown order live in `Src/App/app.cpp`. Only implemented
modules belong in the build; avoid adding empty source files or placeholder targets.
The native window lives in `Src/App/app.qml`; its models and theme manager live
in `Src/FrontEnd/GUI/`. The browser application is in `ui-v2/`.

See the [documentation index](docs/README.md) for guides, design notes, and reviews.
The [maintenance tool index](scripts/README.md) distinguishes catalog generators,
current regression checks, and historical manual scripts.

The control server is the seam: the GUI and the `bin/nullock` CLI are both
thin clients over `/api/*`. New capability = a backing module in
`Src/Core/Networking/` + a `/api/*` handler + a CLI subcommand + tests.

## Build (Windows)

Requires Visual Studio 2022 (MSVC), Qt 6.10.3 (`msvc2022_64`), and
nghttp2 (via vcpkg). **Use the CMake bundled with Visual Studio** —
`C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`.
A standalone CMake on PATH can mis-detect the compiler.

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
  -DNULLOCK_NGHTTP2_ROOT="C:/vcpkg/installed/x64-windows" ^
  -DCMAKE_PREFIX_PATH="C:/Qt/6.10.3/msvc2022_64"
cmake --build build --config Release --target NullockApp
```

Linux/macOS builds use the same CMake project with the platform Qt; see
[`INSTALL.md`](docs/guides/INSTALL.md).

## Run

```sh
# GUI
./build/Src/App/Release/NullockApp

# headless (no QML/browser) -- what CI + scripting use
./build/Src/App/Release/NullockApp --headless --control-port=17777 --proxy-port=8080 --project=/tmp/proj
```

## Test

CI builds and runs all 102 CTest suites on Windows, Linux and macOS,
including local socket and shutdown tests. Use the same full-suite commands locally:

```sh
cmake --build build --config Release --parallel 4
ctest --test-dir build -C Release --output-on-failure --parallel 4
```

Examples of the covered suites:

- `scanner_regression` — every passive detector, positive + negative cases.
- `cve_database` — version→CVE correlation (vulnerable matches, patched
  builds don't, removed entries stay gone, CVSS values).
- `finding_enricher` — every emitted finding kind maps to a non-empty
  CWE/OWASP.
- `request_export` — CSRF-PoC + copy-as-curl transforms (escaping/structure).
- `intruder_engine` — the four attack-type combination generators + marker
  substitution.
- `ci_gate_logic` — the gate's thresholds and exit codes, including that a
  scan which never ran is not a pass (an unreachable target used to exit 0).
- `template_request_logic` — template request building; auto-headers defer to
  the emitted header name, so the tool can't forge a conflicting
  Content-Length.
- `extension_perms_logic` — the permission grammar: which capability
  declarations in an extension's header comment are honoured, and which
  prose-shaped lookalikes are not.
- `extensions_api_grant` — that the `modify-responses` grant is *enforced*,
  not just decided (drives a real `QJSEngine`), and that a granted observer
  can't corrupt a binary body.

Additional CI gates exercise installed packages, application lifecycle and
wire fidelity, project-note persistence, browser tools and two-client note
synchronization, parser sanitizer seeds, active-probe fixtures, website links,
generated catalogs, extension hashes, the CLI and lab syntax. Runtime tests use
isolated temporary profiles and local fixtures. See `.github/workflows/ci.yml`
for the platform-specific commands and `scripts/annotations_regression.py`,
`Tests/ui/annotations_browser_test.cjs` for the project-note workflow checks.

`scripts/integration_smoke.ps1` is the maintained whole-system check (import → CVE
feed → bridge → reports → ScopeGuard) against one headless instance. Earlier
manual scripts are retained in the [legacy archive](scripts/legacy/README.md)
for coverage review.

`scripts/probe_smoke.sh` is the deterministic **active-probe** regression: it
drives the headless server against reliable Python `http.server` mocks and
asserts each probe both fires on a vulnerable target and stays quiet on a safe
one (SQLi, NoSQLi, LDAP, XPath, XXE, SSTI, OS command injection, reflected XSS,
IDOR/BOLA, mass assignment, SSRF, insecure deserialization, open redirect, path
traversal, CORS, verb tampering, server-side prototype pollution, host-header
injection, content discovery, HTTP/3 detection). Run it after touching any probe -- and add a mock mode + assertion
when you add one:

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

Fixture credentials follow the no-literal-secrets rule below: give them the
`nlk_` prefix (Lab 86) or mint them by concatenation at runtime. A real
provider shape (`whsec_`, `sk_live_`, `AKIA…`) in a lab raises a GitHub
secret-scanning alert even though the value is invented (Lab 87, alert #1).

## Commits & PRs

- One logical change per commit; explain *why* in the body.
- Run the test suites before opening a PR; CI must be green.
- Don't commit literal secrets in test fixtures — mint fakes at runtime via
  string concatenation (GitHub push protection scans for key shapes).

## Security issues

Don't open a public issue for a vulnerability in Nullock itself — follow the
disclosure process in [`SECURITY.md`](SECURITY.md).
