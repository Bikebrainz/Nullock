# Nullock

A FOSS, Burpsuite-style MITM HTTP proxy. C++20 + Qt6, CMake build.

The goal is to close the gap between Burpsuite's paywalled "save your project" experience and ZAP's clunky UI — a fast, retro-looking, open-source alternative for web hacking and bug bounty work.

## Build

Requirements:
- CMake 3.24+
- Qt6 (Core, Gui, Qml, Quick, Network)
- A C++20 compiler (MSVC 2022 / GCC 13+ / Clang 16+)
- OpenSSL CLI (for MITM cert generation; on Windows install via `winget install ShiningLight.OpenSSL.Light`). `CertAuthority` looks for `openssl.exe` at the standard `C:\Program Files\OpenSSL-Win64\bin\` location and falls back to PATH.

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

Verified on Windows 11 with MSVC 2022 Community + Qt 6.7.3 (`win64_msvc2019_64`),
proxy round-trips real HTTP and HTTPS traffic via `127.0.0.1:8080`.

## Module status

| Area | File | State | Notes |
|---|---|---|---|
| Proxy core | `Src/BackEnd/Proxy/proxy_server.*` | plain HTTP + HTTPS pass-through, verified end-to-end | no MITM/decryption yet |
| Cert authority | `Src/BackEnd/Proxy/cert_authority.*` | generates root CA on first run; leaf cert minter ready | not wired into the proxy yet — next step |
| Cache | `Src/BackEnd/Cache/cache_handler.*` | empty | response cache, design TBD |
| Networking | `Src/Core/Networking/networking.*` | empty | outbound HTTP for Repeater |
| Database | `Src/Core/Database/database_manager.*` | empty | SQLite for project save/load |
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
- [~] **HTTPS MITM with on-the-fly cert generation** — _in progress._ `CertAuthority` shipped: generates a persistent Nullock Local Root CA at first launch (`%APPDATA%/Nullock/Nullock/ca/ca.pem`) and can mint per-host leaf certs signed by it (via OpenSSL CLI; results cached in memory). Next step: replace the blind CONNECT tunnel in `runTunnel` with a server-side TLS handshake using the leaf cert, then re-encrypt to the real upstream.
- [ ] **Intercept mode** — pause requests in-flight, expose Forward / Drop signals to the GUI.
- [ ] **Scope filter** — glob-based in/out lists between proxy and storage.
- [ ] **Database manager** — SQLite for project persistence ("Load Project File" in the dashboard).
- [ ] **Repeater backend** — `Networking` module to fire arbitrary requests.
- [ ] **Intruder fuzzer**.
- [ ] **Extensions API** — plugin loader and lifecycle.
- [ ] **Themes manager** — JSON-driven theme switching.

## License

MIT. See [LICENSE.md](LICENSE.md).

---

_Last updated: 2026-05-17_
