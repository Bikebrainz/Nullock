# Deploying a hosted OAST tier

Nullock ships an in-process OAST (out-of-band) sink for LAN/internal testing.
To catch callbacks from targets on the public internet — blind SSRF, blind
XXE, log4shell-style RCE, OOB SQLi — you need a sink with a public address.
`nullock-oast` is that: the same `OastServer` the desktop app uses, packaged as
a standalone, headless binary you run on a box you control.

This is the part of the v3 "hosted OAST tier" that needs *you*: a host to run it
on and (ideally) a DNS name. Everything else is built.

## What it does

Two listeners:

| Port (default) | Role |
| --- | --- |
| `OAST_PORT` (8888) | **callback sink** — public; *any* inbound HTTP request is logged as a hit |
| `OAST_ADMIN_PORT` (8889) | **admin API** — `GET /poll`, `POST /mint`, `GET /healthz` (JSON) |

A client mints a token (`POST /mint`), embeds the returned `pathUrl`/`hostUrl`
in a payload, fires it at a target, then polls (`GET /poll?since=N`) for the
callback. Every admin endpoint except `/healthz` requires the admin key.

## Configuration (environment)

| Var | Default | Notes |
| --- | --- | --- |
| `OAST_PORT` | `8888` | callback listener (bind is always `0.0.0.0`) |
| `OAST_BASE_HOST` | `127.0.0.1` | host embedded in minted URLs — set to your public name |
| `OAST_ADMIN_PORT` | `8889` | admin/control listener |
| `OAST_ADMIN_BIND` | `0.0.0.0` | set to `127.0.0.1` if you reach admin only via a tunnel |
| `OAST_ADMIN_KEY` | *(random)* | **set this** — a strong shared secret; a random one is printed at startup if unset |

## Run it

### From source

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target nullock-oast
OAST_BASE_HOST=oast.example.com OAST_ADMIN_KEY=$(openssl rand -hex 16) \
  ./build/Src/Tools/nullock-oast
```

### Docker

```sh
docker build -f packaging/oast/Dockerfile -t nullock-oast .
docker run -d --name oast -p 8888:8888 -p 8889:8889 \
  -e OAST_BASE_HOST=oast.example.com \
  -e OAST_ADMIN_KEY=$(openssl rand -hex 16) \
  nullock-oast
```

## DNS

For the subdomain-form callback URL (`http://<token>.oast.example.com/`) — which
many payloads prefer and which lets one sink serve unlimited tokens — add a
**wildcard A record** pointing at the box:

```
*.oast.example.com.   A   203.0.113.10
oast.example.com.     A   203.0.113.10
```

With only an IP (`OAST_BASE_HOST=203.0.113.10`) the server falls back to the
path-form URL (`http://203.0.113.10:8888/oast/<token>/cb`), which still works
for any target that follows the full URL.

## TLS / reverse proxy

`nullock-oast` speaks plain HTTP. To accept `https://` callbacks (targets that
only follow TLS URLs) and to avoid exposing the admin port directly, front it
with nginx/Caddy:

```nginx
# callbacks: terminate TLS, forward to the sink. DO NOT cache or filter --
# the point is to log whatever arrives.
server {
    listen 443 ssl;
    server_name oast.example.com *.oast.example.com;
    location / { proxy_pass http://127.0.0.1:8888; proxy_set_header Host $host; }
}
```

Then run with `OAST_ADMIN_BIND=127.0.0.1` and reach the admin API over an SSH
tunnel, or proxy it on a separate authenticated vhost. Issue the wildcard cert
with DNS-01 (Let's Encrypt) since HTTP-01 can't validate `*.`.

## Security

- The callback sink is **intentionally open** — it logs every request. Don't put
  a WAF or auth in front of it; that defeats the purpose. Do rate-limit at the
  edge if abuse is a concern (the in-memory log caps at 1000 hits and rolls).
- The admin API is the control plane. **Always set `OAST_ADMIN_KEY`** and
  prefer binding it to localhost behind a tunnel. The key gates `/poll` and
  `/mint`; `/healthz` is open for load-balancer probes only.
- Hits are kept **in memory only** (no disk persistence) and stream to stdout —
  capture them with your container/journald log pipeline if you need history.

## Point a client at it

The minted token's URLs are absolute, so any payload that reaches the target
will call back. To drive it programmatically:

```sh
KEY=your-admin-key
# mint
curl -s -XPOST -H "X-Oast-Key: $KEY" https://oast.example.com/admin/mint
# ... fire the returned pathUrl/hostUrl at your target ...
# poll
curl -s -H "X-Oast-Key: $KEY" "https://oast.example.com/admin/poll?since=0"
```
