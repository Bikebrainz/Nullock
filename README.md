# Nullock

A FOSS, Burpsuite-style MITM HTTP proxy. C++20 + Qt6, CMake build.

The goal is to close the gap between Burpsuite's paywalled "save your project" experience and ZAP's clunky UI — a fast, retro-looking, open-source alternative for web hacking and bug bounty work.

## Build

Requirements:
- CMake 3.24+
- Qt6 (Core, Gui, Qml, Quick, Network)
- A C++20 compiler (MSVC 2022 / GCC 13+ / Clang 16+)
- OpenSSL CLI (for MITM cert generation; on Windows install via `winget install ShiningLight.OpenSSL.Light`). `CertAuthority` looks for `openssl.exe` at the standard `C:\Program Files\OpenSSL-Win64\bin\` location and falls back to PATH.
- libnghttp2 (for HTTP/2 upstream support). Easiest via vcpkg: `vcpkg install nghttp2:x64-windows`. The Proxy CMakeLists picks up `NULLOCK_NGHTTP2_ROOT` (defaults to `D:/vcpkg/installed/x64-windows`); set it via `cmake -DNULLOCK_NGHTTP2_ROOT=...` if your vcpkg lives elsewhere. `nghttp2.dll` must be deployed alongside the exe.

Configure and build (point CMAKE_PREFIX_PATH at your Qt install):

```
cmake -S . -B Build -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_PREFIX_PATH="C:/Qt/6.7.3/msvc2019_64"
cmake --build Build --config Release --target NullockApp
```

On Windows the QML module library needs to live alongside the exe before
running, and Qt's runtime needs to be deployed too:

```
copy Build\Src\FrontEnd\GUI\Release\FrontEndGUI.dll Build\Src\App\Release\
"<Qt>/bin/windeployqt.exe" --release --qmldir Src\App ^
    Build\Src\App\Release\NullockApp.exe
```

Run from the project root so the relative QML path resolves:

```
Build\Src\App\Release\NullockApp.exe
```

## Smoke test

A self-test that exercises the proxy, intercept, and repeater end-to-end
without GUI interaction lives behind a flag:

```
Build\Src\App\Release\NullockApp.exe --smoke-test
```

Exits 0 on pass, 1 on fail. Output (captured via redirected stdout since
the app is a Windows GUI subsystem):

```
PASS  proxy listening on 127.0.0.1:8080
PASS  intercept blocks and forward completes the request
PASS  intercept drop breaks the connection
PASS  repeater send returns a 200 with a real body
PASS  HTTPS MITM end-to-end (h2 upstream, counter 0 -> 1)
smoke test: 5 passed, 0 failed
```

Verified on Windows 11 with MSVC 2022 Community + Qt 6.7.3 (`win64_msvc2019_64`),
proxy round-trips real HTTP and HTTPS traffic via `127.0.0.1:8080`.

## Module status

| Area | File | State | Notes |
|---|---|---|---|
| Proxy core | `Src/BackEnd/Proxy/proxy_server.*` | plain HTTP + HTTPS MITM, HTTP/1.1 keep-alive, **HTTP/2 upstream via libnghttp2**, thread-per-connection, per-host MITM bypass, WebSocket relay after 101 | TLS 1.3, AES-256-GCM-SHA384 negotiated against real hosts |
| HTTP/2 client | `Src/BackEnd/Proxy/http2_client.*` | nghttp2-backed h2 client that takes an established `QSslSocket` (ALPN=h2) and runs one request synchronously, translating the response into our `HttpResponse` so the browser still sees HTTP/1.1 | single stream per CONNECT; no h2 multiplexing or server push |
| Cert authority | `Src/BackEnd/Proxy/cert_authority.*` | generates root CA on first run; leaf cert minter wired into the tunnel; per-host leaves persisted to `ca/leaves/` so restarts reuse them | falls back to blind-pipe if OpenSSL is unavailable |
| Cache | `Src/BackEnd/Cache/cache_handler.*` | empty | response cache, design TBD |
| Networking | `Src/Core/Networking/networking.*` | empty | outbound HTTP for Repeater |
| Storage | `Src/Core/Storage/project_store.*` | working | filesystem-backed project store: per-project directory with `project.json` (scope/notes/metadata) + `history.ndjson` (append-only round-trip log). Auto-streams history into the model on open and auto-appends new traffic. |
| Extensions API | `Src/Core/APIs/ExtensionsAPI/*` | empty | plugin loader |
| Manager API | `Src/Core/APIs/ManagerAPI/*` | empty | central facade |
| App controller | `Src/Core/AppController/*` | empty | C++ ↔ QML wiring |
| Nullem | `Src/Core/Nullem/*` | empty | purpose unclear, needs decision |
| Proxy model | `Src/FrontEnd/GUI/Models/Proxy/*` | working | `QAbstractListModel` populated from `responseReceived`; exposed to QML as `proxyModel` |
| Other GUI models | `Src/FrontEnd/GUI/Models/*` | empty | one per hub |
| Main window | `Src/App/app.qml` | live HTTP History + click-to-inspect | row click opens a side-by-side Request / Response detail pane with full headers and body |
| Other QML hubs | `Src/FrontEnd/GUI/**/*.qml` | stub rectangles | mockups designed but not built |
| Themes | `Src/FrontEnd/GUI/Themes/*` | empty | retro orange/teal palette planned |

## Roadmap

In rough order of dependency:

- [x] **HTTPS via CONNECT tunneling** — pass-through, no decryption. Browsers can route HTTPS through the proxy and traffic flows; each tunnel is logged with host + port.
- [x] **Proxy model + QML binding** — `ProxyModel` (`QAbstractListModel`) fed by `responseReceived` signal. `app.qml` renders an HTTP History table with #, Host, Method, URL, Status, MIME, Params, TLS, IP, Time columns.
- [x] **Click-to-inspect** — selecting a row opens a side-by-side Request / Response detail pane in a resizable split view, showing the full request line, headers, and (textual) body up to 64 KB; binary bodies show a placeholder.
- [x] **HTTPS MITM with on-the-fly cert generation** — `runTunnel` now upgrades the client socket to `QSslSocket` after the CONNECT, presents a forged leaf cert signed by the local Nullock CA, opens a real TLS connection to the upstream host, and shuttles decrypted HTTP between the two halves. Verified end-to-end with `curl -k --proxy http://127.0.0.1:8080 https://httpbin.org/ip`. To make this work in a real browser without warnings, install `%APPDATA%/Nullock/Nullock/ca/ca.pem` as a trusted root authority. Falls back to blind-pipe tunneling when OpenSSL is unavailable.
- [x] **Project persistence (no SQL)** — `ProjectStore` reads/writes a project directory: `project.json` for scope + notes, `history.ndjson` for an append-only stream of round-trips. The default project lives at `%APPDATA%/Nullock/Nullock/projects/default/`. On startup the existing history streams into the model; new traffic auto-appends with `flush()` per line so a crash loses at most one in-flight entry.
- [x] **Scope filter** — glob-based `inScope` / `outOfScope` lists on the project drive the proxy. Out-of-scope hosts still get proxied (browser doesn't break) but skip MITM and never reach the model or `history.ndjson`. Wildcards: `*.example.com`, `*`, etc. Out-of-scope wins over in-scope. `ProjectStore` exposes `addInScope` / `removeInScope` / `setInScope` (and the out variants) as `Q_INVOKABLE` so the GUI can edit live; changes auto-save to `project.json` and re-apply to the running proxy via the `scopeChanged` signal.
- [x] **Persistent MITM bypass list** — `ProxyServer` writes the auto-collected list of cert-pinned hosts to `ca/mitm_blocked.txt` and reloads it on startup so a host that failed once stays bypassed without re-attempting (and re-failing) the TLS handshake. `blockedHosts()` and `clearMitmBlocked()` are Q_INVOKABLE for a future GUI panel.
- [x] **Intercept mode** — toggle on the Intercept tab. When enabled, the proxy worker thread blocks before forwarding a request to upstream; the request lands in the GUI as the "current pending" PendingRequest with its serialized text editable in a TextArea. Forward (with edits) or Drop wakes the worker via a QSemaphore. Multiple in-flight requests queue up — the depth is shown in the status bar's red INTERCEPT (N) indicator. Toggling intercept off forwards everything in the queue at once so traffic doesn't stall.
- [x] **Repeater** — `Networking::HttpClient` opens a raw TCP or TLS connection, writes the request bytes verbatim, parses the response (Content-Length, chunked, or until-close). `Repeater` controller holds editable target host/port/TLS and the raw request/response text, exposed to QML as `repeater`. The Proxy History detail pane has a "Send to Repeater" button that calls `repeater.loadFromHistory(row)` and switches to the Repeater tab; the user can then edit and re-send.
- [ ] **Intruder fuzzer**.
- [ ] **Extensions API** — plugin loader and lifecycle.
- [ ] **Themes manager** — JSON-driven theme switching.

## License

MIT. See [LICENSE.md](LICENSE.md).

---

_Last updated: 2026-05-17_
