# Packaging

How to produce installer artifacts for each platform. Everything here
is free engineering -- no code-signing certs, no Apple Developer
account, no paid CI. Users get a "this publisher is unverified" warning
on first install; documented in `INSTALL.md` as expected.

## Windows -- NSIS installer + portable ZIP

Requires NSIS (free, https://nsis.sourceforge.io/Download).

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target NullockApp
cd build
cpack -G "NSIS;ZIP"
```

Outputs `Nullock-1.0.0-win64.exe` (installer) and
`Nullock-1.0.0-win64.zip` (portable).

## Linux -- DEB / RPM / AppImage

Requires the standard build chain (`dpkg-deb` / `rpmbuild`) plus the
AppImage builder pulls its own.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cd build
cpack -G "DEB;RPM;TGZ"

# AppImage path:
cd ..
DESTDIR=stage cmake --install build --prefix /usr
packaging/appimage/build_appimage.sh stage
```

Outputs:
- `Nullock-1.0.0-Linux.deb`
- `Nullock-1.0.0-Linux.rpm`
- `Nullock-1.0.0-Linux.tar.gz`
- `Nullock-x86_64.AppImage`

The AppImage is the easiest "run anywhere Linux" path -- single file,
no install, no root.

## macOS -- DMG

Requires building on a Mac (no cross-builds for Apple). CPack drives it.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cd build
cpack -G "DragNDrop"
```

Outputs `Nullock-1.0.0-Darwin.dmg`. Unsigned. Users have to
right-click -> Open the first time to bypass Gatekeeper.

## Future: code signing

When we have certs:

- **Windows**: a `signtool sign /fd SHA256 /tr http://timestamp.digicert.com ...`
  step before the `cpack` invocation. NSIS scripts pick up signed exes
  automatically.
- **macOS**: `codesign --deep --force --options runtime --sign "Developer ID Application: ..."`
  on the .app bundle, then `xcrun notarytool submit` for Apple
  notarization, then `stapler staple` on the .dmg.
- **Linux**: most distros don't enforce signing for unofficial repos;
  Flatpak and AppImage have their own signing schemes (also free).

## What we don't ship yet

- Mac DMG (no Mac CI runner; documented for when someone has one)
- Flatpak (manifest needed; not difficult)
- Snap (snapcraft.io account needed for store distribution)
- Microsoft Store (developer account: $19 one-time, deferred)
- Mac App Store (Apple Developer: $99/yr, deferred)
