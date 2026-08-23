# Nullock -- headless web-security toolkit in a container.
#
# Multi-stage: a build stage that mirrors the (green) Linux CI recipe
# (.github/workflows/ci.yml build-linux) using aqtinstall for Qt, and a slim,
# non-root runtime stage. Runs headless (no display) and binds the control API
# off-loopback so you can drive it from the host / CI.
#
#   docker build -t nullock .
#   docker run --rm -p 8080:8080 -p 17777:17777 \
#     -e NULLOCK_API_TOKEN=$(openssl rand -hex 24) nullock
#
#   # one-shot CI gate (exits nonzero on a finding at/above the threshold):
#   docker run --rm nullock --scan https://target.example/ --fail-on high
#
# NOTE: this Dockerfile is derived line-for-line from the known-green Linux CI
# build; it has not yet been validated with `docker build` in this environment.
# Pin Qt/base image digests before relying on it in production.

# --------------------------------------------------------------------------
# Build stage
# --------------------------------------------------------------------------
FROM ubuntu:22.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
ARG QT_VERSION=6.7.3

# NOTE: cmake is deliberately NOT installed via apt here -- Ubuntu 22.04's repo
# ships 3.22.1, but CMakeLists.txt:1 requires 3.24+ (`cmake_minimum_required`
# fails hard before configuring even starts). The GitHub-hosted CI runners this
# Dockerfile otherwise mirrors work around this invisibly: their images ship a
# newer cmake pre-installed ahead of apt's on PATH, so `apt-get install cmake`
# there is a silent no-op. A plain ubuntu:22.04 container has no such override,
# so cmake is installed via pip instead (PyPI ships current upstream releases).
# libfontconfig1-dev / libfreetype-dev / libdbus-1-dev: not needed to configure
# or compile, but the final NullockApp link fails without them -- libQt6Gui.so
# pulls in Fontconfig+FreeType symbols and libQt6DBus.so pulls in libdbus-1
# ones, and a bare ubuntu:22.04 has neither installed (GitHub's hosted runner
# images do, invisibly, which is why the CI build-linux job never needed this).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ninja-build build-essential git \
        libnghttp2-dev libssl-dev zlib1g-dev \
        libfontconfig1-dev libfreetype-dev libdbus-1-dev \
        python3 python3-pip \
        libgl1-mesa-dev libxkbcommon-dev \
    && rm -rf /var/lib/apt/lists/*

# Qt 6.7.x via aqtinstall (the CLI equivalent of the install-qt-action CI uses).
# NOTE: aqtinstall renamed the Linux desktop x86_64 arch from "gcc_64" to
# "linux_gcc_64" as of Qt 6.7.0 (aqtinstall v3.1.12) -- the old name (still
# valid for Qt5) has no package metadata for 6.7+ and made `aqt install-qt`
# fail with "packages ... were not found while parsing XML". The install
# *directory* aqt creates is still named "gcc_64" regardless of arch name,
# so CMAKE_PREFIX_PATH is unaffected.
RUN pip3 install --no-cache-dir aqtinstall cmake \
    && aqt install-qt linux desktop ${QT_VERSION} linux_gcc_64 -m qtwebsockets -O /opt/qt
ENV CMAKE_PREFIX_PATH=/opt/qt/${QT_VERSION}/gcc_64

WORKDIR /src
COPY . .
# `cmake --install ... --component Runtime` (not a manual copy of individual
# build-tree paths) deliberately: root CMakeLists.txt:89-99 already has a
# Linux-specific install(TARGETS FrontEndGUI ...) + INSTALL_RPATH "$ORIGIN" on
# NullockApp, added for exactly this problem (linuxdeploy/AppImage packaging
# needing FrontEndGUI -- a qt_add_qml_module target, the one SHARED lib among
# an otherwise all-STATIC Src/ tree -- installed next to the exe it's not
# statically linked into). Reusing that proven path means NullockApp resolves
# libFrontEndGUI.so via its own RPATH with no extra LD_LIBRARY_PATH entry, and
# the Runtime component also installs ui-v2/templates/extensions in one shot,
# so the runtime stage no longer hand-copies each of those from the source
# tree (a copy that would silently drift if the project ever restructures them).
RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/nullock \
    && cmake --build build --target NullockApp -j \
    && cmake --install build --component Runtime

# --------------------------------------------------------------------------
# Runtime stage
# --------------------------------------------------------------------------
FROM ubuntu:22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive
ARG QT_VERSION=6.7.3

# Runtime counterparts of the build stage's libfontconfig1-dev / libfreetype-dev
# / libdbus-1-dev -- the copied libQt6Gui.so / libQt6DBus.so dlopen these at
# process start (even headless/offscreen), so NullockApp exits immediately with
# "error while loading shared libraries" without them.
#
# GL stack: QT_QPA_PLATFORM=offscreen still needs a real OpenGL context for
# Qt Quick's scene graph (FrontEndGUI is all QML/Quick), and Ubuntu 22.04
# splits GLVND across several packages -- libgl1 alone got as far as
# libOpenGL.so.0 missing (that's libopengl0, a separate package) before this
# was added. libegl1/libgles2 cover the rest of the dispatch libraries a Qt6
# GL context can probe for, and libgl1-mesa-dri ships the actual llvmpipe/
# swrast SOFTWARE driver -- required since GitHub's runners (like most
# containers) have no GPU, so software rasterization is the only path to a
# working GL context at all.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libnghttp2-14 libssl3 libglib2.0-0 libxkbcommon0 \
        libgl1 libopengl0 libegl1 libgles2 libgl1-mesa-dri \
        libfontconfig1 libfreetype6 libdbus-1-3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 nullock

# Qt runtime libraries + plugins (headless still needs the platform plugins).
COPY --from=build /opt/qt/${QT_VERSION}/gcc_64/lib     /opt/qt/lib
COPY --from=build /opt/qt/${QT_VERSION}/gcc_64/plugins /opt/qt/plugins
# NullockApp + libFrontEndGUI.so (CMAKE_INSTALL_BINDIR, RPATH="$ORIGIN" already
# resolves it from there -- see the build stage's `cmake --install` comment)
# + ui-v2/templates/extensions (CMAKE_INSTALL_DATADIR/nullock/*), all from the
# Runtime-component install prefix.
COPY --from=build /opt/nullock/ /usr/local/

ENV LD_LIBRARY_PATH=/opt/qt/lib \
    QT_PLUGIN_PATH=/opt/qt/plugins \
    QT_QPA_PLATFORM=offscreen \
    NULLOCK_UI_DIR=/usr/local/share/nullock/ui

USER nullock
EXPOSE 8080 17777

# Default: headless server bound off-loopback. The app REFUSES a non-loopback
# bind without a token, so NULLOCK_API_TOKEN is REQUIRED here (fail-loud
# otherwise) -- an unauthenticated control API must never be exposed. Override
# the command to run a one-shot `--scan <url> --fail-on <sev>` gate instead
# (that path needs no token and no listener).
ENTRYPOINT ["NullockApp", "--headless", "--listen=0.0.0.0"]
