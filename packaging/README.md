# Packaging Nullock

Build with Qt 6.7.3, CMake 3.24 or newer, and the dependencies in [INSTALL.md](../INSTALL.md). The package version comes from the root CMake project. Always test an installed tree before distributing an artifact.

## Windows

Install Qt's MSVC build, Visual Studio 2022 Build Tools, and `vcpkg install nghttp2:x64-windows openssl:x64-windows`. NSIS is needed for the `.exe` installer; ZIP packaging needs no installer tool.

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH=C:/Qt/6.7.3/msvc2019_64 -DNULLOCK_NGHTTP2_ROOT=C:/vcpkg/installed/x64-windows
cmake --build build --config Release --target NullockApp
cmake --install build --config Release --prefix stage
python scripts/runtime_regression.py stage/bin/NullockApp.exe
cpack --config build/CPackConfig.cmake -G "NSIS;ZIP" -C Release
```

Post-build deployment includes Qt libraries, plugins, QML imports, the Visual C++ runtime, nghttp2, and the OpenSSL executable and dependencies. `NULLOCK_OPENSSL_ROOT` overrides the OpenSSL prefix. CI starts the installed app with a system-only PATH.

## Linux

Qt's deployment script installs the Qt version used for the build, its plugins and QML imports. `patchelf` adjusts deployed library paths. OpenSSL and platform libraries remain native package dependencies. Qt documents the [X11 platform dependencies](https://doc.qt.io/qt-6/linux-requirements.html).

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
cmake --install build --prefix "$PWD/stage"
QT_QPA_PLATFORM=offscreen python3 scripts/runtime_regression.py stage/bin/NullockApp
cpack --config build/CPackConfig.cmake -G 'DEB;RPM;TGZ'
```

DEB needs `dpkg-dev`; RPM needs `rpm`. For AppImage, install `wget` and ImageMagick, then:

```sh
DESTDIR=appimage-stage cmake --install build --prefix /usr
bash packaging/appimage/build_appimage.sh appimage-stage
```

The helper downloads linuxdeploy and its Qt plugin and uses extraction mode to avoid requiring a FUSE mount. Compatibility is bounded by the build's glibc baseline; test each supported distribution.

## macOS

Build on macOS with Qt and `brew install nghttp2`. The system OpenSSL-compatible CLI generates certificates. Qt's deployment script places dependencies in the installed `.app`; web assets, templates, and extensions are under `Contents/Resources/nullock`.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
cmake --install build --prefix "$PWD/stage"
python3 scripts/runtime_regression.py stage/NullockApp.app/Contents/MacOS/NullockApp
cpack --config build/CPackConfig.cmake -G DragNDrop
```

The release workflow signs the fully staged app when signing credentials are configured, then creates and optionally notarizes the DMG. Signing an incomplete build tree before deployment would leave subsequently copied dependencies unsigned.

## Release checks

The release workflow creates a **draft** only when all three platform jobs succeed. Each validates its staged runtime first. Signing remains optional; see [RELEASE_SIGNING.md](../RELEASE_SIGNING.md). Review actual artifacts and checksums before publication.

`NULLOCK_DEPLOY_RUNTIME=OFF` is reserved for environments that provide their own Qt deployment. The Dockerfile uses it because its runtime stage explicitly copies Qt libraries and plugins. CI exercises that container's authenticated API and UI, including certificate initialization and graceful shutdown.

The repository does not provide Flatpak, Snap, Microsoft Store, or Mac App Store packages.
