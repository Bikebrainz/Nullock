#!/usr/bin/env bash
# AppImage builder for Linux. Run AFTER the project is built and
# installed to a staging directory.
#
# Usage:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j
#   DESTDIR=stage cmake --install build --prefix /usr
#   packaging/appimage/build_appimage.sh stage
#
# Produces Nullock-x86_64.AppImage in the current directory. No root,
# no daemons. Works on every Linux distro >= 2015.

set -euo pipefail

STAGE=${1:-stage}
if [ ! -d "$STAGE/usr" ]; then
    echo "stage dir $STAGE/usr not found -- did you run cmake --install?" >&2
    exit 1
fi

# Repo root (this script lives in packaging/appimage/) so we can find the
# shipped logo regardless of the caller's CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# linuxdeploy + the Qt plugin handle Qt-aware bundling. They're both
# free and self-contained.
if ! command -v linuxdeploy >/dev/null 2>&1; then
    echo "downloading linuxdeploy..." >&2
    wget -q "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage" \
        -O linuxdeploy
    chmod +x linuxdeploy
    LD=./linuxdeploy
else
    LD=linuxdeploy
fi

if ! command -v linuxdeploy-plugin-qt >/dev/null 2>&1; then
    echo "downloading linuxdeploy-plugin-qt..." >&2
    wget -q "https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage" \
        -O linuxdeploy-plugin-qt
    chmod +x linuxdeploy-plugin-qt
    export PATH="$PWD:$PATH"
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
# brand-colour square, then a 1x1 PNG.
#
# NB: the old placeholder used `convert -annotate 'Nullock'`, which pulls
# ImageMagick's default 'helvetica' font. That font isn't installed on CI
# runners, so the build died with "unable to read font `helvetica'". Never use
# -annotate/-draw text here without shipping a font.
ICON="$STAGE/usr/share/icons/hicolor/256x256/apps/nullock.png"
LOGO="$REPO_ROOT/Src/FrontEnd/Resources/nullock_logo.png"
if [ ! -f "$ICON" ]; then
    if command -v convert >/dev/null 2>&1 && [ -f "$LOGO" ]; then
        convert "$LOGO" -resize 256x256 "$ICON"
    elif command -v convert >/dev/null 2>&1; then
        convert -size 256x256 xc:'#9d4edd' "$ICON"
    else
        # Synthesize a 1x1 transparent PNG as a last resort.
        printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xcf\xc0\x00\x00\x00\x03\x00\x01\xc8\xd7\xd5\xa0\x00\x00\x00\x00IEND\xaeB`\x82' \
            > "$ICON"
    fi
fi

# Produce the AppImage.
"$LD" --appdir "$STAGE" \
    -d "$STAGE/usr/share/applications/nullock.desktop" \
    -i "$STAGE/usr/share/icons/hicolor/256x256/apps/nullock.png" \
    --plugin qt \
    --output appimage

ls -lh Nullock-*-x86_64.AppImage 2>/dev/null || ls -lh *.AppImage
echo "Built. Run as ./Nullock-x86_64.AppImage."
