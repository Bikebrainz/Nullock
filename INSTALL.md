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

## Build from source

### Prerequisites
- **Qt 6.7.3** (module `msvc2019_64` on Windows; distro/Homebrew Qt 6
  elsewhere), with `qtwebsockets`.
- A C++20 compiler (MSVC 2022 / recent GCC / Clang) and CMake ≥ 3.24.
- **nghttp2** (HTTP/2). Windows: `vcpkg install nghttp2:x64-windows`.
- OpenSSL (for the forged-leaf CA).

### Windows (MSVC)
Use the VS-bundled CMake (see [`CONTRIBUTING.md`](CONTRIBUTING.md)):
```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
  -DNULLOCK_NGHTTP2_ROOT="C:/vcpkg/installed/x64-windows" ^
  -DCMAKE_PREFIX_PATH="C:/Qt/6.7.3/msvc2019_64"
cmake --build build --config Release --target NullockApp
```
The app lands at `build\Src\App\Release\NullockApp.exe`.

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
