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

# Use a placeholder icon if we don't ship one. linuxdeploy needs SOMETHING.
if [ ! -f "$STAGE/usr/share/icons/hicolor/256x256/apps/nullock.png" ]; then
    # A 256x256 PNG with the literal text "Nullock" works as a stop-gap.
    # `convert` is part of ImageMagick which is in every distro.
    if command -v convert >/dev/null 2>&1; then
        convert -size 256x256 xc:'#0d0d12' \
            -fill '#9d4edd' -gravity center \
            -pointsize 36 -annotate 0 'Nullock' \
            "$STAGE/usr/share/icons/hicolor/256x256/apps/nullock.png"
    else
        # Synthesize a 1x1 transparent PNG as a last resort.
        printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xcf\xc0\x00\x00\x00\x03\x00\x01\xc8\xd7\xd5\xa0\x00\x00\x00\x00IEND\xaeB`\x82' \
            > "$STAGE/usr/share/icons/hicolor/256x256/apps/nullock.png"
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
