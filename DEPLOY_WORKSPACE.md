# Deploying a team workspace (findings sync)

`nullock-workspace` is the Phase-1 MVP of [design/team-workspaces.md](design/team-workspaces.md):
a small, self-hostable server that lets several operators share an engagement's
**findings**. Clients push their local findings and pull teammates' deltas; the
server merges by the same finding identity key the desktop app uses for
baseline/diff (`kind | host | url | summary`), so findings line up across
operators with no translation.

This is the part of the v3 "team workspaces" item that needs *you*: a host to
run it on. The engineering is built.

## MVP scope (and what is deferred)

| Area | MVP | Deferred to |
| --- | --- | --- |
| Storage | SQLite (one file) | Postgres adapter (design phase 3) |
| Auth | one shared bearer key | per-user OIDC/SSO + roles ([enterprise-sso.md](design/enterprise-sso.md)) |
| Sync | findings push/pull, last-write-wins by identity key, monotonic seq | comments/assignment, shared history, real-time push (phase 2-3) |

## Configuration (environment)

| Var | Default | Notes |
| --- | --- | --- |
| `WORKSPACE_PORT` | `8790` | listener port |
| `WORKSPACE_BIND` | `0.0.0.0` | bind address |
| `WORKSPACE_DB` | `nullock-workspace.sqlite` | SQLite path — mount on a volume |
| `WORKSPACE_KEY` | *(random)* | **set this** — the shared team secret; a random one is printed at startup if unset |

## Run it

```sh
# from source
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target nullock-workspace
WORKSPACE_KEY=$(openssl rand -hex 16) ./build/Src/Tools/nullock-workspace

# docker
docker build -f packaging/workspace/Dockerfile -t nullock-workspace .
docker run -d --name ws -p 8790:8790 \
  -e WORKSPACE_KEY=$(openssl rand -hex 16) \
  -e WORKSPACE_DB=/data/workspace.sqlite -v nullock-ws:/data \
  nullock-workspace
```

Front it with a TLS reverse proxy (same as `DEPLOY_OAST.md`) for production.

## API

All endpoints except `/healthz` require the key (`X-Workspace-Key: <key>` header
or `?key=`).

```
GET  /healthz
POST /api/ws/push   { engagement, name?, author?, findings: [ {kind,host,url,summary,severity,...}, ... ] }
       -> { ok, engagement, newSeq, accepted }
GET  /api/ws/pull?engagement=<id>&since=<seq>
       -> { ok, engagement, seq, count, findings: [...] }
```

Typical client loop: `pull?since=<last seq>` to fetch teammates' changes, then
`push` your new/changed findings; persist the returned `seq` as your new cursor.

```sh
KEY=your-team-key
curl -s -H "X-Workspace-Key: $KEY" -XPOST \
  -d '{"engagement":"acme-2026","findings":[{"kind":"sql-injection","host":"app.acme","url":"https://app.acme/x","summary":"SQLi in id","severity":"high"}]}' \
  https://ws.example.com/api/ws/push
curl -s -H "X-Workspace-Key: $KEY" "https://ws.example.com/api/ws/pull?engagement=acme-2026&since=0"
```

## Security

- Always set `WORKSPACE_KEY` to a strong secret; anyone with it can read/write
  every engagement's findings. Per-user auth + roles is the SSO track.
- Findings can contain sensitive target data — run on infrastructure you
  control, encrypt the volume, and put TLS in front.
- Hits are persisted to the SQLite DB only; no telemetry.
