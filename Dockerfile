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

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build build-essential git \
        libnghttp2-dev libssl-dev \
        python3 python3-pip \
        libgl1-mesa-dev libxkbcommon-dev \
    && rm -rf /var/lib/apt/lists/*

# Qt 6.7.x via aqtinstall (the CLI equivalent of the install-qt-action CI uses).
RUN pip3 install --no-cache-dir aqtinstall \
    && aqt install-qt linux desktop ${QT_VERSION} gcc_64 -m qtwebsockets -O /opt/qt
ENV CMAKE_PREFIX_PATH=/opt/qt/${QT_VERSION}/gcc_64

WORKDIR /src
COPY . .
RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --target NullockApp -j

# --------------------------------------------------------------------------
# Runtime stage
# --------------------------------------------------------------------------
FROM ubuntu:22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive
ARG QT_VERSION=6.7.3

RUN apt-get update && apt-get install -y --no-install-recommends \
        libnghttp2-14 libssl3 libglib2.0-0 libgl1 libxkbcommon0 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 nullock

# Qt runtime libraries + plugins (headless still needs the platform plugins).
COPY --from=build /opt/qt/${QT_VERSION}/gcc_64/lib     /opt/qt/lib
COPY --from=build /opt/qt/${QT_VERSION}/gcc_64/plugins /opt/qt/plugins
# The app + its runtime assets (ui-v2, detection templates, extensions).
COPY --from=build /src/build/Src/App/NullockApp /usr/local/bin/NullockApp
COPY --from=build /src/ui-v2       /usr/local/share/nullock/ui
COPY --from=build /src/templates   /usr/local/share/nullock/templates
COPY --from=build /src/extensions  /usr/local/share/nullock/extensions

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
