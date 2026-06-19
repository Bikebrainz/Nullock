# nullock-workspace -- deployable team-workspace findings-sync server.
#
# Build (context = repo root):
#   docker build -f packaging/workspace/Dockerfile -t nullock-workspace .
# Run (persist the SQLite DB on a volume):
#   docker run -d --name ws -p 8790:8790 \
#     -e WORKSPACE_KEY=$(openssl rand -hex 16) \
#     -e WORKSPACE_DB=/data/workspace.sqlite \
#     -v nullock-ws:/data \
#     nullock-workspace
#
# Only the nullock-workspace target is compiled; the runtime image keeps just
# the Qt libs it loads (Core + Network + Sql) plus the SQLite driver plugin.

# ---- build stage ----------------------------------------------------------
FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build g++ \
        qt6-base-dev qt6-declarative-dev qt6-websockets-dev \
        libnghttp2-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build --target nullock-workspace

# ---- runtime stage --------------------------------------------------------
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        libqt6core6 libqt6network6 libqt6sql6 libqt6sql6-sqlite ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/Src/Tools/nullock-workspace /usr/local/bin/nullock-workspace

# Set WORKSPACE_KEY to a strong secret in any real deployment (a random one is
# generated and printed to the logs each start otherwise), and point WORKSPACE_DB
# at a mounted volume so the findings persist across restarts.
ENV WORKSPACE_PORT=8790 \
    WORKSPACE_BIND=0.0.0.0 \
    WORKSPACE_DB=/data/workspace.sqlite
VOLUME ["/data"]
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD ["sh","-c","curl -fsS http://127.0.0.1:${WORKSPACE_PORT}/healthz || exit 1"]

ENTRYPOINT ["/usr/local/bin/nullock-workspace"]
