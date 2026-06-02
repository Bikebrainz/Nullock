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

### Request / response framing safety
- **CL+TE smuggling defence.** The proxy's request and response parsers refuse any message that carries both `Content-Length` and `Transfer-Encoding` headers, or that carries duplicate `Content-Length` values with conflicting numbers, or a `Content-Length` whose value isn't a single non-negative integer. A hostile upstream that frames a response two ways at once would otherwise let us pick one length and the browser pick the other, turning one captured response into two on the keep-alive socket.

### Resource exhaustion (extended)
- **Slowloris on control server.** Header read enforces a hard 10s wall-clock deadline per connection (separate from the per-`waitForReadyRead` budget) so a client dribbling one byte every 4.9s can't pin the main thread forever. Body read enforces a 30s deadline on the same basis.
- **`/api/search` ReDoS.** Patterns are capped at 4 KB. Patterns whose shape matches a nested-unbounded-quantifier heuristic (`(...*)*`, `(...+)+`, `({n,})+`, etc.) are refused before they hit the matcher. Each scanned body is truncated to 1 MB and the loop visits at most 500 rows. Qt's PCRE backend doesn't expose a match-timeout so this is best-effort, but it converts the textbook bombs into a 400.
- **nmap XML import: XXE / billion-laughs.** `<!DOCTYPE` and `<!ENTITY` in the body are refused up-front. Element nesting is capped at 64. QXmlStreamReader's default behaviour of ignoring external entities is the primary defence; these guards make sure a future Qt change (or a parser swap) can't silently re-open the hole.
- **WebSocket reassembly buffer.** Per-stream `m_buf` is capped at 2× the max frame payload (32 MiB). On overflow the parser drops its state and stops emitting frame events for that stream; the raw relay still forwards bytes so the user's app keeps working. Without this cap, 100 hostile streams declaring 16 MiB frames and dribbling bytes would pin 1.6 GiB.

### Intercept queue integrity
- **Toggle-race fix.** `addPendingOnMain` re-checks `m_enabled` under the mutex; if the user (or a project switch) disabled intercept during the race window between `pend()`'s atomic check and the queued slot dispatch, the request is released as an immediate forward rather than parked in `m_queue` forever. Without this, the worker thread that called `pend()` would block on `p->done` indefinitely and the captured request bytes (including auth headers) would sit resident until process death.

### State hygiene across projects / engagements (extended)
- **Repeater, Intruder, intercept queue clear on project switch.** R2's `historyShouldClear` wiring now also fires `Repeater::clearAll`, `Intruder::clearAll`, and `intercept.forwardAll()/setEnabled(false)`. A request loaded into Repeater (with Engagement A's Authorization header) no longer survives a project switch to Engagement B.
- **Project store I/O race.** `m_history` is now guarded by `m_historyMutex` across `open()`, `close()`, and `appendEntry()`. A worker thread mid-write while the main thread closed the file would previously have written into a closed `QFile` whose underlying FD may have been recycled by the OS to another open file in this process (CA private key, theme JSON).
- **Imported M&R rule quarantine.** When loading a project's rules from disk, any rule whose host pattern is a catch-all (`*`, `.*`, empty) AND whose `find`/`replace` touches a credential-shaped header name (Cookie, Authorization, Bearer, X-API-Key, etc.) loads with `enabled = false` and a `[QUARANTINED on load]` tag in its comment. Defends against the project-file-from-a-DM exfil pattern, where a shared project shim drops a "duplicate Cookie into a new header" rule that any in-scope target then echoes back to the attacker.

### Shutdown safety
- **QtConcurrent task drain.** Main returns via `QThreadPool::globalInstance()->waitForDone(5000)` so in-flight port scan / probe / replay workers (whose lambdas capture raw pointers into the App-scope Wiring struct) get up to 5 seconds to finish before the stack unwinds out from under them.

### CA private key file ACL
- **Owner-only ACL on `ca.key`.** After generating (or on every startup, for pre-existing keys) the CA private key file's DACL is rewritten to a single ACE granting only the current user `GENERIC_ALL`, with inheritance disabled. On POSIX this is `chmod 0600`. Anyone with the CA private key can forge certs for any host the user trusts — Nullock's installed CA is treated as a root by the user's browser, so a leaked key trivially produces TLS-green spoofs of `bank.com` and the like.

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
- **`QThread::create` in `proxy_server::onNewConnection` lifetime on shutdown.** `~ProxyServer` doesn't track its own worker threads (only the QtConcurrent ones are now drained via the global pool in main). Practical impact remains "crash on shutdown only," but a future fix should track each connection's QThread and join in the destructor.

### Medium
- **Per-handler thread pool on control server.** Slowloris is now bounded by the wall-clock deadlines added in this pass, but `handle()` is still synchronous-on-main. A single slow request still blocks others up to its deadline. Move handlers onto a thread pool to fully decouple.

## What to do if you find something

If you're a security researcher and you've found a vulnerability that isn't already on the "known gaps" list above, please open a private security advisory on GitHub (Security → Advisories → "Report a vulnerability") rather than a public issue.

For the things on the "known gaps" list, PRs welcome — but please touch one item per PR and include a regression test or repro script.
