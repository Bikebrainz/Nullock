# Security model

Nullock is, by design, a tool that handles untrusted bytes — captured HTTP traffic from the wire, responses from arbitrary upstreams, user-supplied JS extensions, regex rules, project files. This document covers what the codebase defends against, the audit findings that were fixed, and the known gaps.

## Threat model

| Actor | What they can do | What we defend against |
|---|---|---|
| **Local user** (running Nullock on their machine) | Trusted. Owns the project, can install extensions, can run any code. | Not the adversary. |
| **Malicious upstream HTTP server** | Sends arbitrary response bytes to a request the user proxied through us. | Buffer overflows, CRLF injection into captured cookies that we re-inject, regex catastrophic backtrack via response body, OOM via oversize body / chunked. |
| **Malicious local web page** (loaded in the user's browser) | Can `fetch()` `127.0.0.1` URLs from JavaScript, embed `<img src>` to GET endpoints, submit forms cross-origin. | CSRF against `/api/*` writes, exfiltrating captured session/cred state. |
| **Network attacker between us and a real origin** | Replaces an upstream server's bytes in transit (e.g. by spoofing DNS or MITMing a Cloudflare-fronted host). | Treated identically to "malicious upstream" — we don't currently verify upstream TLS chains, so this is **not fully mitigated** (see "Known gaps"). |
| **Malicious extension author** | Drops `.js` files into the extensions dir. | Limited — JS extensions are explicitly trusted by virtue of being installed; we validate the wire-bytes they produce but not their intent. |

## What we defend against (verified)

These were caught and fixed during the multi-subsystem audit logged in commits `1732247` and `d56174b`.

### CSRF / API access
- **Origin check** on every state-mutating endpoint. Same-origin (`http://127.0.0.1:<port>`) OR an explicit `X-Nullock-UI: 1` custom header. Empty `Origin` is no longer treated as trusted — that previously let `file://`-loaded HTML and Electron-style wrappers slip through.
- **Method enforcement**: read endpoints accept `GET`; everything else returns `405` unless POST'd. Previously the path-based dispatcher accepted any method, so a `<img src="http://127.0.0.1:17777/api/history/5/probe">` could fire the active probe cross-origin.
- **Method allowlist** at the request parser drops unknown verbs at the door.
- **Active probe scope check** — refuses to fire payloads (`'`, `;id;#`, `../../etc/passwd`, CRLF) at hosts that aren't in the project's scope. Previously a malicious local page could pivot Nullock into attacking arbitrary hosts the user had once browsed.
- **DNS rebinding defence** — the control server validates the `Host` request header against the allowed set (`127.0.0.1[:port]`, `localhost[:port]`, `[::1][:port]`). A drive-by page that resolves an attacker-controlled hostname first to a public IP (to get the script loaded) and then to `127.0.0.1` (to talk to Nullock) gets rejected with `421 Misdirected Host` because the browser still sends `Host: rebind.attacker.example`.

### Upstream TLS
- **Explicit peer-cert verification** on the MITM upstream socket and on the Repeater/Scanner/Replay socket. `setPeerVerifyMode(VerifyPeer)` + `setPeerVerifyName(host)` set explicitly at the call site; an `sslErrors` handler captures and surfaces the underlying reason without ever calling `ignoreSslErrors()`. A network attacker between Nullock and a real origin can no longer present a forged cert and have us forward its decrypted bytes as "TLS" to the browser — the upstream handshake collapses and the tunnel dies.

### State hygiene across projects / engagements
- **Cross-project session clear** — switching projects fires `historyShouldClear`, which now also wipes `SessionManager`. Cookies captured against `target-A.example` while pentesting Engagement A are no longer replayed into Engagement B's requests when the user switches.

### Export / clipboard credential safety
- **Centralized sensitive-header policy** (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token`, `X-CSRF-Token`, `X-XSRF-Token`, `X-Session-Id`, `X-Amz-Security-Token`, `X-Goog-IAM-Authorization-Token`) is applied uniformly to:
  - HAR export (default on; `redact:false` in the POST body to opt out)
  - Postman collection export (default on; `?raw=1` query to opt out)
  - "Copy as curl / wget / httpie / powershell / fetch" renderers in the UI
  Lets a tester share a HAR with a triager or paste a "copy as curl" into a bug report without also sharing their session.
- **NDJSON query-string suppression** — the `--ndjson` event stream strips `?token=…` from `path` and `url` fields by default. A tester piping `--ndjson` into a log file (or sharing a screenshot of their terminal) no longer leaks bearer tokens out of band. Pass `--ndjson-include-query` to opt in to the raw query string.

### Path traversal
- **Project names** validated against `[A-Za-z0-9_\- .]{1,64}` with Windows reserved-name (`CON`, `NUL`, `COM1-9`, `LPT1-9`, `AUX`) blocklist, no leading/trailing dot or space, no NUL byte, no control chars, no `..`.
- **Theme names** same validation. `saveTheme("../../../poison", ...)` would have written outside the themes dir; now refused.
- **HAR import** path refuses UNC paths, requires the target to be a regular readable file, caps at 256 MB.
- Static-file `safeJoin` strips leading separators and refuses `..` substrings.

### HTTP smuggling / CRLF injection
- **Session manager** strips `\r`, `\n`, `\0`, and C0 control bytes from captured `Set-Cookie` names and values before storing — preventing a hostile upstream from embedding header splits that we'd replay on subsequent outgoing requests for that host.
- **JS extension boundary** validates every returned method / path / header / status / reason-phrase. Header names must be RFC 7230 tokens; values reject `\r`, `\n`, `\0`, other C0; method must be `A-Z`+; status clamped `100..599`; path rejects whitespace and CR/LF. Invalid values fall back to the pre-mutation original.
- **crt.sh recon** validates the domain to `[A-Za-z0-9.\-]{1,253}` before composing the request line.

### Resource exhaustion
- **Control server `/api/*` body size** capped at 64 MB; `Content-Length` validated (no negative, no overflow) with `413` returned on excess.
- **HttpClient response body** capped at 128 MB across `readUntilClose`, `readExact`, and chunked decode; negative or oversize chunk sizes refused.
- **Session manager cookies per host** capped at 256 (LRU drop-oldest).
- **Recon wordlist** capped at 2000 entries per request to bound concurrent UDP DNS sockets.
- **crt.sh response parse** capped at 32 MB.
- **Port scanner** `parallel` clamped `[1, 256]`, `timeoutMs` clamped `[50, 30000]`, `throttleMs` clamped `[0, 60000]`, total tasks (`hosts × ports`) capped at 100,000.

### Regex / ReDoS
- **Match & Replace** patterns now pre-compiled once at `setRules()` time. Patterns over 4 KB are refused. Pre-compiling means a CPU-pathological pattern only burns CPU during rule-edit, not on every captured request. Qt's PCRE backend doesn't expose a match-timeout, so a deliberately catastrophic pattern (`(a+)+$`) is still a CPU DoS during traffic; we mitigate via the pattern-size cap and treat this as "you own the rules you write."

### Cert authority hardening
- **Hostname validation** before invoking openssl: refuses leading `-` (option-parsing trap), leading `_`, control bytes, anything outside `[A-Za-z0-9._-]{1,253}`, leading/trailing dot, `..`.
- Arguments to `openssl` go through `QProcess::setArguments` (no shell interpolation).
- Subject and SAN ext file content are confined to validated hostnames.

## Known gaps (not yet fixed)

These were surfaced by the audit but not addressed in this pass. Listed so the next person reading the code knows what's open and where to start.

### High
- **Request smuggling: CL+TE.** Proxy parsers tolerate a request/response carrying both `Content-Length` and `Transfer-Encoding: chunked`, picking one. If upstream picks differently from us, requests desync. Fix is to reject any message with both headers, and reject duplicate `Content-Length` with differing values.
- **Slowloris on control server.** `onNewConnection → handle()` is single-threaded synchronous. A single client opening a socket and dribbling 1 byte every 4.9s holds the main thread. Fix: move handlers to a thread pool, or use async chunked reads with a per-connection deadline.
- **Intercept toggle race.** A request that enters `pend()` after `setEnabled(false)` (but before the lock check) can sit in `m_queue` forever; the worker thread leaks. Re-check `m_enabled` inside `addPendingOnMain` under the mutex.
- **WebSocket buffer cap.** `m_buf` has no upper bound; a hostile upstream declaring a 16 MiB frame then dribbling bytes parks 16 MiB per connection. Cap `m_buf.size()` and drop the parser if exceeded.
- **QObject lifetime on shutdown.** Several worker threads (`QThread::create` in `proxy_server::onNewConnection`, `QtConcurrent::run` in port scanner / probe / replay) capture `this` or wiring pointers. `~ProxyServer` doesn't drain in-flight workers. Practical impact is "crash on shutdown only," but a future fix should track in-flight tasks and wait.

### Medium
- **`/api/search` ReDoS.** User regex runs against every captured body with no match-timeout. Same fundamental problem as Match & Replace — Qt's PCRE doesn't expose a budget. Wrap in `QtConcurrent::run` with a hard wall-clock cap, or reject patterns containing nested quantifiers.
- **`Wiring` raw-pointer captures.** Lambdas in the control server's probe/replay/probe-all paths capture `Wiring` by value (which copies pointers). If the user switches projects or the app shuts down mid-task, the captured pointers dangle. Switch to `QPointer<>` or look up state on the main thread at fire time.
- **Project store race.** `appendEntry()` from worker threads can race `close()` from main. Hold the project's file under a mutex covering open/write/close.

## What to do if you find something

If you're a security researcher and you've found a vulnerability that isn't already on the "known gaps" list above, please open a private security advisory on GitHub (Security → Advisories → "Report a vulnerability") rather than a public issue.

For the things on the "known gaps" list, PRs welcome — but please touch one item per PR and include a regression test or repro script.
