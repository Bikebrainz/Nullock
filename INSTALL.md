# Installing Nullock

Two ways: grab a release binary, or build from source.

## Release binaries

Download the latest from
[Releases](https://github.com/Bikebrainz/Nullock/releases/latest):

- **Windows** — `Nullock-<ver>-win64.exe`, run it.
- **Linux** — `.deb` (`sudo apt install ./Nullock-<ver>-Linux.deb`),
  `.rpm` (`sudo dnf install ./Nullock-<ver>-Linux.rpm`), or the AppImage
  (`chmod +x Nullock-x86_64.AppImage && ./Nullock-x86_64.AppImage`).
- **macOS** — `Nullock-<ver>-Darwin.dmg`; right-click → Open the first time
  (binaries are not yet notarized).

The CLI `nullock` (in `bin/`) talks to a running instance over
`$NULLOCK_API` (default `http://127.0.0.1:17777`); it needs `curl` + `jq`.

Packages built from this revision use Qt 6.10.3 and require Windows 10 1809+
or macOS 13+. Linux x86-64 packages are built and tested on Ubuntu 22.04.
The CI-built macOS disk image targets Apple silicon; Intel Macs require a
source build with an Intel toolchain and dependencies.
See [Qt's supported platforms](https://doc.qt.io/qt-6.10/supported-platforms.html)
for the runtime baseline.

## Build from source

### Prerequisites
- **Qt 6.10.3**, **including the `qtwebsockets` module** (it is a *separate*
  add-on — a base Qt install without it will fail to configure). The QML / Quick
  / Sql / Network / Concurrent modules ship in the base Qt 6 install. This is the
  minimum version accepted by CMake and the version CI builds against.
- A C++20 compiler (MSVC 2022 / GCC 12+ / Clang 15+) and CMake ≥ 3.24.
- **nghttp2** dev headers (HTTP/2) and **OpenSSL** dev headers (forged-leaf CA).
  These are the two dependencies most often missing — install them explicitly:
  - **Linux (Debian/Ubuntu):** `sudo apt-get install build-essential cmake ninja-build libnghttp2-dev libssl-dev openssl patchelf libxcb-cursor0`
  - **Linux (Fedora):** `sudo dnf install gcc-c++ cmake ninja-build libnghttp2-devel openssl-devel openssl patchelf`
  - **macOS:** `brew install nghttp2 openssl@3`; the system OpenSSL-compatible command-line tool generates certificates.
  - **Windows:** `vcpkg install nghttp2:x64-windows openssl:x64-windows`; the build deploys the OpenSSL CLI and Qt runtime.

### Windows (MSVC)
Use the VS-bundled CMake (see [`CONTRIBUTING.md`](CONTRIBUTING.md)):
```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
  -DNULLOCK_NGHTTP2_ROOT="C:/vcpkg/installed/x64-windows" ^
  -DCMAKE_PREFIX_PATH="C:/Qt/6.10.3/msvc2022_64"
cmake --build build --config Release --target NullockApp
```
The app lands at `build\Src\App\Release\NullockApp.exe`.
Its browser assets and runtime dependencies are deployed alongside the build.
See [packaging](packaging/README.md) to create and validate an installer.

### Linux / macOS
```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$(qmake6 -query QT_INSTALL_PREFIX)"
cmake --build build -j --target NullockApp
```

## First run

```sh
NullockApp --proxy-port=8080 --control-port=17777
```
Then trust the CA it generates (so it can read TLS), point your browser's
proxy at `127.0.0.1:8080`, and — importantly — **set a scope** before you
browse, so it captures the target and not your own traffic:

```sh
nullock scope add 'https://target.example/*'
nullock status
nullock scan target.example top100
```

Full quickstart: <https://bikebrainz.github.io/Nullock/docs/index.html>

Use `--project=PATH` to open an explicit project directory, or `--data-dir=PATH`
to isolate app data (CA, projects, extensions, and preferences). Unknown or
malformed options produce an error instead of silently using the default project.

Project switching and clearing history are refused while requests, scans, or proxy
connections are active. Finish or stop that work first. Clear History removes the
saved history and findings for the current project and resets its browser row
identity. Binary requests opened in Repeater or Intruder use explicit Latin-1
byte mode; UTF-8 mode is available for text editing. Intruder's `§...§` delimiters
identify payload positions.
