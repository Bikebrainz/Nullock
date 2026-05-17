# Nullock

A FOSS, Burpsuite-style MITM HTTP proxy. C++20 + Qt6, CMake build.

The goal is to close the gap between Burpsuite's paywalled "save your project" experience and ZAP's clunky UI — a fast, retro-looking, open-source alternative for web hacking and bug bounty work.

## Build

Requirements:
- CMake 3.24+
- Qt6 (Core, Gui, Qml, Quick, Network)
- A C++20 compiler (MSVC 2022 / GCC 13+ / Clang 16+)

```
cmake -S . -B Build -DCMAKE_PREFIX_PATH="<path to Qt6>"
cmake --build Build
./Build/Src/App/NullockApp
```

## Module status

| Area | File | State | Notes |
|---|---|---|---|
| Proxy core | `Src/BackEnd/Proxy/proxy_server.*` | plain HTTP + HTTPS pass-through | no MITM/decryption yet |
| Cache | `Src/BackEnd/Cache/cache_handler.*` | empty | response cache, design TBD |
| Networking | `Src/Core/Networking/networking.*` | empty | outbound HTTP for Repeater |
| Database | `Src/Core/Database/database_manager.*` | empty | SQLite for project save/load |
| Extensions API | `Src/Core/APIs/ExtensionsAPI/*` | empty | plugin loader |
| Manager API | `Src/Core/APIs/ManagerAPI/*` | empty | central facade |
| App controller | `Src/Core/AppController/*` | empty | C++ ↔ QML wiring |
| Nullem | `Src/Core/Nullem/*` | empty | purpose unclear, needs decision |
| Proxy model | `Src/FrontEnd/GUI/Models/Proxy/*` | empty | feeds HTTP History table |
| Other GUI models | `Src/FrontEnd/GUI/Models/*` | empty | one per hub |
| QML hubs | `Src/FrontEnd/GUI/**/*.qml` | stub rectangles | mockups designed but not built |
| Themes | `Src/FrontEnd/GUI/Themes/*` | empty | retro orange/teal palette planned |

## Roadmap

In rough order of dependency:

- [x] **HTTPS via CONNECT tunneling** — pass-through, no decryption. Browsers can route HTTPS through the proxy and traffic flows; each tunnel is logged with host + port.
- [ ] **Proxy model + QML binding** — wire `requestReceived` / `responseReceived` signals into a `QAbstractListModel` so the GUI HTTP History table updates live. (Picking this next gives visible payoff — the GUI finally does something.)
- [ ] **HTTPS MITM with on-the-fly cert generation** — generate per-host certs from a local CA so we can decrypt and inspect TLS traffic.
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
