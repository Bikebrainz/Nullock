# Security review — whole codebase (multi-agent findings, "maybefix")

**Method.** MADS multi-agent evidence debate — five independent reviewers (Codex `gpt-5.6-sol`, Grok 4.5, Kimi K3, plus two memory-blind Claude reviewers, Opus and Fable), each in an isolated worktree. Round 1 blind independent review over the whole tree → an orchestrator evidence pass that verified loci → anonymized cross-examination where reviewers attacked each other's findings and killed/narrowed weak ones. Reviewed at `1ae72a5` (branch `Nullock`). Fable's Round-2 lane hit a transient 529 while writing its verdicts (its R1 findings are included; its partial R2 confirmed no additional memory-safety defect in the DNS parser); Round-2 external quorum is the three external vendors plus Opus.

**This PR changes no code.** It adds this one document, and is **not intended to merge** — it is a triage container ("maybefix") to work through later. Fixes are left to you. A prior review (PR #1) covered the HTTP-header/token cluster; this pass deliberately ranged the rest of the tool: the intercepting proxy + control backend, the ~63 scanner/tester decision modules, TLS/OAST/crypto, storage, extensions, and the CI action.

**What held up well** (the reviewers' negative pass): the raw-byte parsers (WebSocket frame, zlib/content-decode, nghttp2, DNS), the marketplace/extension loader (allowlist + fail-closed sha256), storage path-traversal guards, and ~15 scanner verdict modules (CORS/cmd-injection/nosql/XXE/etc.) were independently traced and found sound. The findings cluster in the CI action, the control backend, credential handling, and a handful of scanner false-positive/negative edges — for a scanner, a wrong verdict is a core failure (a false negative hides a real vuln; a false positive fails a CI gate).

| # | Sev | Type | One line | Locus |
|---|-----|------|----------|-------|
| 1 | **CRITICAL** | RCE (CI) | `nullock-scan` action interpolates `${{ inputs.* }}` into a bash `run:` block → command injection on a consumer's runner (steals GITHUB_TOKEN + secrets) | `.github/actions/nullock-scan/action.yml:33-38` |
| 2 | **HIGH** | memory-safety | `isSensitive` indexes the original `fn` with offsets computed from `fn.toLower()`; `toLower()` can lengthen a string (U+0130) so a target-controlled GraphQL field name drives an out-of-bounds read | `Src/BackEnd/Control/control_server.cpp:6921-6934` |
| 3 | **HIGH** | credential leak | "Redacted" HAR export redacts headers only — URL query, `queryString`, and POST body stay raw, so `access_token`/`X-Amz-Signature`/OAuth codes leak into the shareable artifact | `Src/Core/Storage/project_store.cpp:785-808` |
| 4 | **HIGH** | DoS | Close-delimited `readUntilClose` appends every chunk with no total cap (CL path caps at 128 MiB, chunked at 256 MiB) → a hostile upstream streaming forever exhausts proxy memory | `Src/BackEnd/Proxy/proxy_server.cpp:210-217,968-972` |
| 5 | **HIGH** | false positive | Error-based SQLi trusts WAF-carryable MSSQL/SQLite prose as an ungated DBMS fingerprint → a quote-selective WAF echoing those phrases is CONFIRMED as critical SQLi (the class Oracle prose was already demoted for) | `Src/Core/Networking/sql_logic.cpp:27-36` |
| 6 | MEDIUM | false negative | `/api/audit/all?fromHistory` rebuilds the target with only Content-Type — never Cookie/Authorization — so authenticated endpoints are probed bare and reported clean | `Src/BackEnd/Control/control_server.cpp:7358-7378` |
| 7 | MEDIUM | wrong-verdict-tag | `finding_enricher.cpp` defines 8 map keys twice in a `QHash` initializer; the later insert wins, so 3 detectors emit an order-dependent, self-contradictory CWE/CVSS (csp-unsafe-inline CWE-79→693, crlf CWE-93→113, web-cache-deception A04/7.5→A05/6.5) | `Src/Core/Networking/finding_enricher.cpp` |
| 8 | MEDIUM | self-compromise | Standalone OAST prints the generated admin key to stdout while binding the admin API to `0.0.0.0` → authority to read callbacks + mint tokens leaks via ordinary logs | `Src/Tools/oast_server_main.cpp:173-221` |
| 9 | MEDIUM | false negative | SSRF auto-detect probes only the FIRST recognized query key and stops, so a real sink later in the query (`url=` after `path=`) is never tested | `Src/Core/Networking/ssrf_scan.cpp:96-104` |
| 10 | MEDIUM | false positive | Subdomain-takeover reports HIGH (CWE-284) from a body-text fingerprint alone — no DNS/CNAME/status gate — so a 200 page quoting branded copy yields a high finding | `Src/Core/Networking/takeover_scan.cpp:9-18` |
| 11 | MEDIUM | weak-RNG | OAST correlation tokens come from `QRandomGenerator::global()` (non-CSPRNG) and any registered-token hit auto-confirms a high/critical finding → a replayed/guessed token fabricates a "confirmed" finding | `Src/Core/APIs/Oast/oast_server.cpp:174-175` |
| 12 | MEDIUM | DoS | Control-server header read runs on the main thread with a 10 s deadline BEFORE bearer validation and no concurrency cap → off-loopback, N slow connections serialize into ~10 s × N of API/UI freeze (self-documented) | `Src/BackEnd/Control/control_server.cpp:975-1020` |
| 13 | LOW | privacy footgun | `/api/triage/finding` POSTs ≤16 KiB of captured request+response (cookies/Authorization) to a caller-supplied `ollama` URL with no host allowlist (operator-configured, CSRF-gated, default loopback) | `Src/BackEnd/Control/control_server.cpp:5244-5304` |
| 14 | LOW | fingerprinting | `/ca.pem` + `/ca.crt` set `Access-Control-Allow-Origin: *` on a CSRF-exempt GET, so any site can read the **public** CA cert cross-origin + confirm Nullock + probe the port (contradicts the file's own no-ACAO invariant; not the private key) | `Src/BackEnd/Control/control_server.cpp:1179` |
| 15 | LOW | credential exposure | Workspace-sync accepts the shared team key via `?key=` while default-binding `0.0.0.0` → key lands in intermediary/proxy logs (header `X-Workspace-Key` is the documented alt; key also printed to stdout) | `Src/Tools/workspace_server_main.cpp:148-167` |
| 16 | LOW | path confinement | `/api/har/import` opens a JSON `path` with no base-dir confinement, but only surfaces HAR-shaped JSON `log.entries` (non-JSON returns −1 → nothing imported); CSRF-gated to loopback/same-origin | `Src/Core/Storage/project_store.cpp:955-982` |

**Rejected in cross-examination (do not chase):** an empty-`Host` "fail-open" in `control_logic.cpp:11-12` — three reviewers killed it: browsers always send `Host`, off-loopback requires a bearer token *before* the Host gate, and loopback read-methods are intentionally unauthenticated anyway; it's documented + unit-tested. (One reviewer flagged it as fail-closed hygiene — harmless to change, but not a defect.)

---

## 1 — CRITICAL · CI action command injection

`.github/actions/nullock-scan/action.yml:33-38` builds the scan command by textual interpolation:

```
args=( --scan "${{ inputs.url }}" --fail-on "${{ inputs.fail-on }}" )
echo "::group::nullock --scan ${{ inputs.url }} ..."
"${{ inputs.binary }}" "${args[@]}"
```

GitHub Actions substitutes `${{ }}` into the script text **before** bash parses it, so a consumer wiring an attacker-influenceable value into an input — `url: https://${{ github.head_ref }}...` on a fork PR (branch names allow `` ; | & $ ( ) ` ``, and `$IFS` defeats the space restriction), or a `url` derived from a PR/issue body — executes arbitrary commands on the runner with the job's `GITHUB_TOKEN` and secrets (CWE-78/94). *4 of 5 reviewers found this independently; all SUSTAIN.* **Direction:** bind each input to the step `env:` (`env: { URL: ${{ inputs.url }} }`) and reference the quoted shell var (`--scan "$URL"`); never put `${{ }}` inside `run:`.

## 2 — HIGH · Out-of-bounds read in the GraphQL sensitive-field check

`control_server.cpp:6921-6934`: `isSensitive(fn)` computes `const QString l = fn.toLower();`, finds token offsets `idx`/`after` in `l`, then reads `fn[idx]` / `fn[after]` — bounding only `after >= l.size()` (against `l`, never `idx < fn.size()`). Qt's `toLower()` can **lengthen** a string (U+0130 'İ' → "i" + U+0307), so a target-controlled GraphQL introspection field name of `100×U+0130 + "password"` gives `fn.size()=108`, `l.size()=208`, and `fn[200]` reads ~184 bytes past the buffer (release builds compile out `QString`'s bounds assert). The name is attacker-controlled (`:6948`, from the scanned endpoint's introspection schema) with only a 16 MiB whole-body cap and no per-name validation. Harm is UB / crash → a scan-time DoS (the read only feeds a boolean), not a confirmed info-leak. *SUSTAIN by both blind lanes + both externals that reached it.* **Direction:** index `l` consistently (`l[idx]`, `l[after]`), or guard every `fn[k]` with `k < fn.size()`.

## 3 — HIGH · "Redacted" HAR export leaks query-string and body credentials

`project_store.cpp:785-808`: default-redacted HAR export (`m_exportRedact=true`) redacts credential *headers* but writes the URL (full path+query), each `queryString` entry, and `postData.text` / response body verbatim. A captured request with `?access_token=…&X-Amz-Signature=…`, or an OAuth code / bearer in the body, survives into the `.har` the redaction exists to make shareable. *SUSTAIN ×3.* **Direction:** redact known credential-bearing query keys and body fields (or mark the export "unredacted" honestly).

## 4 — HIGH · Unbounded close-delimited response read (proxy memory DoS)

`proxy_server.cpp:210-217` (`readUntilClose`) appends `readAll()` in a loop with no total-size cap, while the Content-Length path caps at 128 MiB and the chunked path at 256 MiB (`:954-959`). A hostile upstream that streams bytes forever without stalling the per-read idle timeout grows the proxy's RSS without bound. *SUSTAIN ×3.* **Direction:** apply the same total-size cap the other two body paths use.

## 5 — HIGH · SQLi confirmed from WAF-carryable error prose (false positive)

`sql_logic.cpp:27-36`: MSSQL/SQLite error strings ("Unclosed quotation mark", "Incorrect syntax near", "unrecognized token") are treated as DBMS-specific fingerprints on **any** status — the exact class Oracle prose was already demoted out of; only the `generic` signature is status-gated. A quote-selective WAF whose block page echoes those phrases (and clears the balanced-quote control) yields a **confirmed critical** SQLi that isn't real. *SUSTAIN (narrowed to those specific prose signatures).* **Direction:** gate the MSSQL/SQLite prose the same way Oracle's was (status + differential), not on presence alone.

## 6–12 — MEDIUM

**6 · Auth-stripped deep audit (false negative).** `/api/audit/all?fromHistory` rebuilds the `AuditTarget` with only Content-Type; `runDeepAudit` feeds `t.headers` (Cookie/Authorization absent) to every tester, and there's no session re-attach on the audit path — so authenticated endpoints are probed unauthenticated and reported clean. *Fix: carry the captured Cookie/Authorization (or the session jar) into the fromHistory target.*

**7 · Enricher CWE/CVSS collisions (wrong verdict tag).** `finding_enricher.cpp`'s `QHash` initializer defines 8 keys twice; later inserts win, so the first mapping is dead and three detectors ship contradictory tags: `csp-unsafe-inline` (CWE-79 → CWE-693), `crlf-injection` (CWE-93 → CWE-113), `web-cache-deception` (A04/7.5/`S:U C:H` → A05/6.5/`S:C`). Several entries also carry a `cvssScore` that disagrees with their own `cvssVector` (`cookie-no-secure` 5.3 vs a 7.5 vector). *Fix: de-duplicate the table (one entry per key) and reconcile score↔vector.*

**8 · OAST admin key to stdout on 0.0.0.0.** Standalone OAST prints the generated admin bearer to stdout while binding the admin API to all interfaces — the key reaches journald/docker logs, granting callback-read + token-mint to a log reader with network reach. *Fix: bind loopback by default, and don't print the key (write it to a file with restricted perms).*

**9 · SSRF single-param coverage gap (false negative).** `ssrf_scan.cpp:96-104` breaks on the first query key present in `knownSsrfParams()`, so `?path=/x&url=http://sink` probes only `path` and never the real `url` sink. *Fix: probe every recognized param (or the highest-signal one), not just the first.*

**10 · Subdomain-takeover from body text alone (false positive).** `takeover_scan.cpp` reports HIGH/CWE-284 on a body fingerprint with no DNS/CNAME resolution and no status gate — a normal 200 page quoting "There isn't a GitHub Pages site here." is flagged high. (Reviewers split on whether this trips the *default* CI gate vs only the active/UI scan; the false-positive itself is agreed.) *Fix: require an error status + a DNS/CNAME check before "takeover"; demote body-only to "possible".*

**11 · Non-CSPRNG OAST tokens + blind auto-confirm.** `oast_server.cpp:174-175` mints correlation tokens from `QRandomGenerator::global()` (Qt-documented non-cryptographic), and any registered-token hit auto-creates a confirmed high/critical finding. Full Mersenne-Twister state recovery is impractical here (needs ~312 consecutive outputs; the global generator is process-shared and interleaved), so this is weak-RNG best-practice + a **token-replay** fabrication path, not a demonstrated predictor. *Fix: mint from `QRandomGenerator::system()` (as the tool already does for admin keys); consider not auto-confirming on token-match alone.*

**12 · Pre-auth main-thread header-read DoS.** `control_server.cpp:975-1020`: header reading runs synchronously on the main thread with a 10 s absolute deadline *before* bearer validation, with no concurrency cap — so off-loopback, N unauthenticated slow-header connections serialize into ~10 s × N of API/UI freeze (the code comment concedes the aggregate gap). *Fix: read headers off the main thread / cap concurrent pre-auth connections / shorten the pre-auth deadline.*

## 13–16 — LOW

**13 · Triage → operator ollama, no allowlist.** `/api/triage/finding` POSTs ≤16 KiB of captured request+response (cookies/Authorization) to a caller-supplied `ollama` URL with no host allowlist. Operator-configured, CSRF-gated, default `127.0.0.1:11434` — a privacy footgun if the operator points ollama off-box, not remote exfil. *Fix: allowlist the ollama host (or warn when non-loopback).*

**14 · `/ca.pem` cross-origin readable.** `control_server.cpp:1179` sets `ACAO: *` on the CSRF-exempt cert GET, so any website can read the **public** CA cert cross-origin, confirm Nullock is running, and probe the candidate ports — contradicting the file's own no-ACAO invariant for private state. It's the public cert, not `ca.key`, so harm is cross-origin fingerprinting. *Fix: drop `ACAO: *` from the cert routes (serve same-origin like every other route).*

**15 · Workspace key via `?key=`.** Accepting the shared team key as a query param while default-binding `0.0.0.0` lands the credential in intermediary/proxy logs; the key is also printed to stdout. *Fix: accept the key only via the `X-Workspace-Key` header; bind loopback by default; don't print it.*

**16 · HAR-import base-dir confinement.** `/api/har/import` opens a JSON `path` with only exists/isFile/isReadable/UNC/256 MB checks and no root confinement — but it only imports HAR-shaped `log.entries` (non-JSON returns −1, so arbitrary bytes never surface), and is CSRF-gated to loopback/same-origin. Defense-in-depth, not arbitrary file read. *Fix: confine `path` under the projects dir (the same `safeJoin` the static server uses).*

---

*Generated by a multi-agent review debate; findings are advisory and were verified by code read, not by running the tool against a live target. No source was modified. Severities are the reviewers' consensus after cross-examination.*
