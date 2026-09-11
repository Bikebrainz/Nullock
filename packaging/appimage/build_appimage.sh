#!/usr/bin/env bash
# AppImage builder for Linux. Run AFTER the project is built and
# installed to a staging directory.
#
# Usage:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j
#   DESTDIR="$PWD/stage" cmake --install build --prefix /usr
#   packaging/appimage/build_appimage.sh stage
#
# Produces Nullock-x86_64.AppImage in the current directory. No root,
# no daemons. The target distro must support the build's glibc baseline.

set -euo pipefail
export APPIMAGE_EXTRACT_AND_RUN=1

STAGE=${1:-stage}
if [ ! -d "$STAGE/usr" ]; then
    echo "stage dir $STAGE/usr not found -- did you run cmake --install?" >&2
    exit 1
fi

# Repo root (this script lives in packaging/appimage/) so we can find the
# shipped logo regardless of the caller's CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# CMake has already deployed the selected Qt plugins, QML imports and qt.conf.
# linuxdeploy finishes the native dependency bundle and creates the AppImage.
if ! command -v linuxdeploy >/dev/null 2>&1; then
    echo "downloading linuxdeploy..." >&2
    wget -q "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage" \
        -O linuxdeploy
    chmod +x linuxdeploy
    LD=./linuxdeploy
else
    LD=linuxdeploy
fi

# Drop a desktop entry + icon into the stage.
mkdir -p "$STAGE/usr/share/applications" "$STAGE/usr/share/icons/hicolor/256x256/apps"
cat > "$STAGE/usr/share/applications/nullock.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Nullock
Comment=FOSS web security toolkit
Exec=NullockApp
Icon=nullock
Categories=Network;Security;Development;
Terminal=false
EOF

# linuxdeploy needs an icon. Prefer the REAL shipped logo, resized to 256x256 --
# a pure raster op with NO font dependency. Fall back to a font-free solid
# brand-colour square. linuxdeploy requires a supported square icon size.
#
# NB: the old placeholder used `convert -annotate 'Nullock'`, which pulls
# ImageMagick's default 'helvetica' font. That font isn't installed on CI
# runners, so the build died with "unable to read font `helvetica'". Never use
# -annotate/-draw text here without shipping a font.
ICON="$STAGE/usr/share/icons/hicolor/256x256/apps/nullock.png"
LOGO="$REPO_ROOT/Src/FrontEnd/Resources/nullock_logo.png"
if [ ! -f "$ICON" ]; then
    if command -v convert >/dev/null 2>&1 && [ -f "$LOGO" ]; then
        convert "$LOGO" -resize 256x256 -gravity center -background none -extent 256x256 "$ICON"
    elif command -v convert >/dev/null 2>&1; then
        convert -size 256x256 xc:'#9d4edd' "$ICON"
    else
        echo "ImageMagick is required to generate the 256x256 package icon" >&2
        exit 1
    fi
fi

# Produce the AppImage.
"$LD" --appdir "$STAGE" \
    --executable "$STAGE/usr/bin/NullockApp" \
    -d "$STAGE/usr/share/applications/nullock.desktop" \
    -i "$STAGE/usr/share/icons/hicolor/256x256/apps/nullock.png" \
    --output appimage

ls -lh Nullock-*-x86_64.AppImage 2>/dev/null || ls -lh *.AppImage
echo "Built. Run as ./Nullock-x86_64.AppImage."
