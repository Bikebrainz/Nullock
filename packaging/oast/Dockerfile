# nullock-oast -- deployable OAST callback sink.
#
# Build (context = repo root):
#   docker build -f packaging/oast/Dockerfile -t nullock-oast .
# Run:
#   docker run -d --name oast -p 8888:8888 -p 8889:8889 \
#     -e OAST_BASE_HOST=oast.example.com \
#     -e OAST_ADMIN_KEY=$(openssl rand -hex 16) \
#     nullock-oast
#
# Only the tiny nullock-oast target is compiled (--target nullock-oast pulls in
# just Qt Core + Network + oast_server.cpp), but the top-level configure step
# still evaluates the whole project's find_package() calls, so the build stage
# installs the full dependency set. The runtime image keeps only the two shared
# Qt libs the binary actually loads.

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
 && cmake --build build --target nullock-oast

# ---- runtime stage --------------------------------------------------------
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        libqt6core6 libqt6network6 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/Src/Tools/nullock-oast /usr/local/bin/nullock-oast

# Defaults; override at `docker run` time. OAST_BASE_HOST should be the public
# wildcard hostname that resolves to this container, and OAST_ADMIN_KEY MUST be
# set to a strong secret in any real deployment (otherwise a random one is
# generated and printed to the logs each start).
ENV OAST_PORT=8888 \
    OAST_ADMIN_PORT=8889 \
    OAST_ADMIN_BIND=0.0.0.0 \
    OAST_BASE_HOST=127.0.0.1

EXPOSE 8888 8889

# Liveness: the unauthenticated /healthz endpoint on the admin port.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD ["sh","-c","curl -fsS http://127.0.0.1:${OAST_ADMIN_PORT}/healthz || exit 1"]

ENTRYPOINT ["/usr/local/bin/nullock-oast"]
