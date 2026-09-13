> **Triage status (2026-09-12):** source PR #1 closed.
> **HIGH #1 FIXED** (`abb6559`, header-audit redirect follower is same-origin-only) and
> **HIGH #2 FIXED** (`a5b3cb6`, JWT probe strips secondary credentials on both shots).
> **MEDIUM #3 and #4 FIXED** ([PR #16](https://github.com/Bikebrainz/Nullock/pull/16)): confirmation requires cookie-only
> credentials and a transported credential-free 401/403 denial; captured
> handshake headers are regenerated. Browser cookie delivery still requires
> verification in the target's context. Regression coverage lives in
> [the WebSocket unit suite](../../Tests/ws_probe/ws_probe_test.cpp) and
> [the active-probe smoke fixtures](../../scripts/probe_smoke.sh).
> **#6 and #7 FIXED:** nonce/hash validation and effective script directives now
> have native and browser regression coverage. **#11 FIXED** in
> [PR #17](https://github.com/Bikebrainz/Nullock/pull/17). **#10 reassessed:** an
> explicit frame-ancestor allow-list still restricts framing; see below.
> Findings **#5, #8 and #9 remain recorded for follow-up** against the current source.

# Security review — HTTP-header / token cluster (`Src/Core/Networking`)

**Method:** Static code review of the HTTP-header and token-handling cluster. Findings were checked against the cited source locations; this review did not exercise live targets.

**Scope:** `header_logic`, `host_header_logic`/`host_header`, `jwt_probe_logic`/`jwt_probe`/`jwt_tool`, `smuggling_logic`, `crlf_logic`, `ws_logic`/`ws_probe`, and the entry points that feed them attacker-controlled bytes. Reviewed at `23937ba` (branch `Nullock`).

**Status:** This document records historical findings for triage. The dated status above identifies the fixes recorded at the time; remaining findings require verification against the current source.

**What held up well:** no memory-corruption defect was found in this cluster — attacker-byte parsing uses bounds-checked `QByteArray`/`QString` APIs throughout; the WebSocket frame path is bounded (16 MiB frame cap, 32 MiB buffer cap, 64 MiB inflate cap, guarded mask/XOR). JWT forge/verify is sound: the tool never locally "accepts" a token, `bruteHmac` refuses non-HS tokens, and `alg:none` / HS↔RS confusion / blank-secret / `kid` are each independently gated. The findings are almost entirely **verdict-correctness** issues — for a scanner, a wrong verdict is the core failure mode: a false **negative** hides a real vulnerability from the user; a false **positive** destroys trust in every other result.

| # | Sev | Type | One line | Locus |
|---|-----|------|----------|-------|
| 1 | **HIGH** | credential leak + scope | Header-audit redirect follower gates on hostname only, follows `https→http`/port changes, forwards the captured `Cookie`/`Authorization` over cleartext, and binds the new origin's verdicts to the original URL | `header_audit.cpp:34-65`, `header_logic.cpp:449-463` |
| 2 | **HIGH** | false positive | JWT probe strips secondary credentials only on the no-token calibration shot, so forged-token shots keep a session `Cookie` and a cookie-auth endpoint is reported as a signature/algorithm bypass | `jwt_probe_logic.cpp:73-99` |
| 3 | MEDIUM | false positive | CSWSH "CONFIRMED" fires when the credential-stripped baseline is any non-101 (transport error `0`, `429`/`5xx` from its own origin sweep), and treats a caller-set `Authorization: Bearer` a browser can't attach as an ambient credential | `ws_probe.cpp:108-125`, `ws_logic.cpp:38-43` |
| 4 | MEDIUM | false negative | CSWSH handshake builder carries a stale `Sec-WebSocket-Key`/`Connection`/`Upgrade` from the captured request → duplicate key (RFC 6455 §4.1) → `expectedAccept()` fails → vulnerable endpoint graded "no upgrade" | `ws_logic.cpp:106-118` |
| 5 | MEDIUM | false negative | Only the **first** `Content-Security-Policy` header is audited; browsers enforce the intersection of all of them, so a weak first policy plus a strict second cries wolf (`allHeaderValues` already exists, used for `Set-Cookie`) | `header_logic.cpp:22-26,279-289` |
| 6 | MEDIUM | false negative | A syntactically invalid CSP nonce/hash (`'nonce-!'`) passes a length-only check, sets `hasNonceOrHash`, and suppresses the HIGH `csp-unsafe-inline` finding though browsers discard the malformed source | `header_logic.cpp:137-172` |
| 7 | MEDIUM | false negative | Bypassable-gadget-host audit walks only `script-src`/`default-src`; a clean `script-src` plus a known gadget host on `script-src-elem`/`script-src-attr` is graded clean while `<script>` still loads it | `header_logic.cpp:184-224` |
| 8 | MEDIUM | false negative | No `jku`/`x5u` key-substitution lead — the remote-JWKS/SSRF surface (arguably worse than `kid`, which *is* flagged) produces no hint; `decode()` extracts only `alg`/`typ`/`kid` | `jwt_tool.cpp:66-68,124-133` |
| 9 | MEDIUM | false negative | Host-header-injection URL-context detector misses CSS `url(//host…)`, so a reflection into a stylesheet `url()` sink is graded a bare reflection, not URL-context injection | `host_header_logic.cpp:22-26` |
| 10 | LOW | false negative (narrow) | `frame-ancestors 'none' https://evil` is graded protective; per CSP3 the `'none'` is ignored beside other sources, so an author who meant deny-all silently allows framing (siblings have `effectivelyNone`; this path doesn't) | `header_logic.cpp:258-270` |
| 11 | LOW | false negative (rare) | Active `alg:none` forgeries re-serialize the payload via `QJsonDocument` (reordering keys) instead of preserving `rawPayloadB64`, missing a byte/order-sensitive verifier that `forgeNone` already handles | `jwt_probe_logic.cpp:133-146` |
| — | info | not a defect | WebSocket 64-bit length uses a signed `<<` shift, but the build pins C++20 (where signed left-shift is defined, modulo-2^N) and the negative/oversize guard rejects the result before any consumer reads it — UBSan-flaggable only if ever built pre-C++20 | `Src/BackEnd/Proxy/websocket.cpp:55-67` |

---

## 1 — HIGH · Redirect follower forwards credentials to cleartext and mis-binds verdicts

`auditHeaders` follows up to two redirects to audit the real landing page. Its comment says "SAME-ORIGIN redirects," but the gate is hostname-only:

```
if (next.host().compare(req.host, Qt::CaseInsensitive) != 0) break;   // off-origin
effTls = (next.scheme() == "https");
cur.port = next.port(effTls ? 443 : 80);
```

A response `https://victim/a → Location: http://victim:8080/b` passes the host check, and the follower then re-issues the request over the new scheme/port. `buildRequest` copies `req.headers` and drops only framing headers (`Content-Length`/`Transfer-Encoding`/`Accept-Encoding`/`Connection`) — **`Cookie` and `Authorization` are re-emitted**, now over a plaintext connection (verified through `networking.cpp` opening a plain TCP socket and writing those bytes). Two further consequences: the response's header verdicts are reported against the original URL (`control_server.cpp:8176-8178` binds to the pre-redirect `url`), and the silent `https→http` downgrade skips the `effTls`-gated HSTS / `Secure`-cookie checks entirely.
**Direction:** require normalized scheme+host+port equality before following, and never carry credentials across an origin/scheme change.

## 2 — HIGH · JWT probe retains a session cookie on forged shots → false bypass

The secondary-credential strip is gated on the no-token calibration shot only:

```
if (token.isEmpty() && isCredentialHeader(h.first)) continue;   // no-token shot only
```

On a forged/corrupted-token shot (`token` non-empty) a carried `Cookie: session=…` is kept, so a cookie-authenticated endpoint that ignores JWTs stays authorized — the differential (no-token denied, forged allowed) is reported as a **signature/algorithm bypass** that does not exist. A unit test (`jwt_probe_test.cpp:132-133`) currently locks the buggy behavior ("WITH a token, the Cookie credential is kept").
**Direction:** strip every non-target credential from calibration **and** attack requests; replace, don't duplicate, the tested carrier.

## 3–9 — MEDIUM

**3 · CSWSH confirmation is unsound (two mechanisms).** `confirmed = !(base.status == 101 && base.acceptValid)` treats *any* non-101 credential-stripped baseline as a session refusal — a transport drop (`status 0`), or a `429`/`5xx` provoked by the ~8-handshake origin sweep that precedes it — yielding a false "CONFIRMED hijack" against a session-blind public socket. Separately, `hasCredential()` counts an `Authorization: Bearer` header that a cross-site browser's WebSocket API cannot attach. *Fix: only a genuine transported auth-refusal (a real 401/403 with `base.ok`) may confirm; `status ≤ 0`/`429`/`5xx` are inconclusive; treat caller-injected Bearer as a lead, not a browser-ambient credential.*

**4 · CSWSH false negative (stale key).** The handshake builder skips only `Host`/`Origin`, so a captured `Sec-WebSocket-Key` is appended after the builder's fresh one; an RFC-6455-compliant server rejecting the duplicate returns a 101 whose Accept fails `expectedAccept()`, and a vulnerable endpoint is graded safe. *Fix: also drop `Connection`/`Upgrade`/`Sec-WebSocket-Key`/`Sec-WebSocket-Version` from carried headers.*

**5 · Only the first CSP header is audited.** `headerValue` is first-wins; browsers enforce every CSP header (intersection), so a permissive first policy atop a strict second raises findings the browser already blocks — a proven false-positive-only direction. *Fix: audit every value via `allHeaderValues` and report a weakness only when no enforced policy blocks it.*

**6 · Invalid CSP nonce suppresses a HIGH finding.** The nonce/hash acceptance checks prefix + closing quote + non-empty only, so `'nonce-!'` (invalid base64) neutralizes `csp-unsafe-inline` though the browser discards the malformed source and inline script still runs. *Fix: validate nonce/hash syntax (and digest length) before letting it cancel `unsafe-inline`.*

**7 · Gadget-host bypass missed on `script-src-elem`/`-attr`.** The bypassable-host loop walks only `script-src`/`default-src`; the element/attr override loop checks `unsafe-inline`/`eval`/wildcards but never the gadget-host list. *Fix: apply the gadget-host check to the element/attr directives too.*

**Resolved and corrected (2026-09-12), #6–#7:** malformed nonce/hash values no
longer suppress the unsafe-inline finding. Nonces use the ASCII source grammar;
hashes must additionally decode. Digest length is not a suppression requirement:
Chromium accepts a decodable short hash even though it cannot match a SHA digest.
The historical recommendation to validate digest length was therefore incorrect.
Gadget hosts and broad external sources are checked in the effective
`script-src-elem` list, including its fallback. `script-src-attr` governs event
handlers and cannot authorize external script URLs. Eval uses `script-src` or
`default-src`. Restrictive overrides and `strict-dynamic` no longer produce
findings for ignored base/host sources. See the
[native suite](../../Tests/header_audit/header_audit_test.cpp),
[Chromium differential suite](../../Tests/ui/csp_browser_test.cjs), and
[CSP3 directive definitions](https://www.w3.org/TR/CSP3/#directive-script-src-elem).

**8 · No `jku`/`x5u` lead.** `decode()` surfaces `kid` but not `jku`/`x5u`; a token steering key resolution to an attacker JWKS URL gets no hint (zero `jku`/`x5u` references repo-wide). Narrowed: the raw header is preserved in the decoded struct, and parameter presence is a *lead*, not proof of server-side dereference. *Fix: extract `jku`/`x5u` and emit a key-substitution/SSRF test lead parallel to `kid`.*

**9 · Host-header injection into `url()` under-graded.** `bodyHasUrl` matches `://s`, `"//s`, `'//s`, `=//s` but not CSS `url(//host…)`, so a reflection into a stylesheet `url()` sink stays `inUrlContext=false`. *Fix: add the `url(` protocol-relative context.*

## 10–11 — LOW (follow-up assessment)

**10 · `frame-ancestors 'none' https://evil` graded protective.** Narrow but real: the detector credits any non-wildcard `frame-ancestors` list as protective, so the specific footgun where an author writes `'none'` and appends an origin (CSP3 ignores the `'none'`) suppresses `clickjacking-missing`. *Fix: reuse the `effectivelyNone` sole-expression rule.*

**Reassessed (2026-09-12):** the historical conclusion above conflates deny-all
with restricted framing. Once `'none'` is ignored, the explicit origin allow-list
still blocks other ancestors under [CSP3](https://www.w3.org/TR/CSP3/#directive-frame-ancestors).
That satisfies the existing `clickjacking-missing` check for a restrictive policy.
No production change is warranted for this example; native regressions preserve
the distinction between an explicit origin and a wildcard. Inferring whether
the configured origin is trusted requires target context.

**11 · `alg:none` payload reserialization.** Real consistency gap — `algNoneVariants` re-serializes where `forgeNone` preserves `rawPayloadB64` — but `alg:none` has no signature and JSON claims are order-independent, so the missed surface is only a rare byte/order-sensitive verifier. *Fix: reuse `forgeNone`'s raw-payload preservation on the active path.*

**Resolved (2026-09-12):** all six active variants now preserve `rawPayloadB64`
when available. Constructed claims without a captured segment still serialize
normally. The [JWT probe regression suite](../../Tests/jwt_probe/jwt_probe_test.cpp)
covers captured whitespace/key order, JSON escapes and numeric spelling, plus
the constructed-claims fallback.

---

*Findings are advisory and based on static code inspection. This review did not modify source or validate findings against a live target.*
