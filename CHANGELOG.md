# Changelog

All notable changes to Nullock are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/). Dates are when a build went out.

The public, prose version lives at
<https://bikebrainz.github.io/Nullock/changelog.html>; this file is the
developer-facing record.

## [Unreleased]

### Added
- **Extensions can save their own settings and state.** An extension can now keep
  data across restarts with a small key/value store &mdash; <code class="inline">nullock.storage.set(key, value)</code>,
  <code class="inline">get(key, default)</code>, <code class="inline">has</code>,
  <code class="inline">keys</code>, <code class="inline">remove</code>,
  <code class="inline">clear</code> (Burp's <code class="inline">persistence().extensionData()</code>).
  It holds strings, numbers, and nested objects/arrays, persists to disk outside the
  extensions folder (so saving never triggers auto-reload), and comes back after a
  restart. The store is shared across extensions, so give your keys a prefix.
- **Extensions can auto-reload while you're developing them.** Turn on auto-reload
  (launch with <code class="inline">--ext-autoreload</code>, set
  <code class="inline">NULLOCK_EXT_AUTORELOAD</code>, or <code class="inline">POST /api/extensions/auto-reload {value:true}</code>)
  and editing, adding, or removing an extension file reloads your extensions
  automatically &mdash; no more clicking Reload after every change. It's off by
  default so a stateful extension isn't torn down on an unrelated save, and the
  reloads are debounced so one save is one reload.
- **Extensions can run their own out-of-band (OOB) checks.** A JavaScript extension
  can now mint a Collaborator-style payload with <code class="inline">nullock.collaborator.generate()</code>
  (Burp's <code class="inline">api.collaborator()</code>), drop it into a request, and
  later read back any interactions it triggered with <code class="inline">nullock.collaborator.interactions()</code>
  &mdash; the DNS and HTTP callbacks a target made to that payload, each with its
  token, source IP, timing, and request details. That's the building block for
  extension-written SSRF, blind-injection, XXE, and log4shell checks; interactions
  are scoped to the tokens that extension generated. (SMTP interactions and the full
  raw callback body are still to come.)
- **Individual extensions can be turned off without deleting them.** Disabling one
  extension used to mean physically moving its file out of the extensions folder
  and reloading. Now each extension has an enable/disable state: turn one off and
  it stays on disk and in the list but stops running (no globals, no handlers),
  turn it back on and it loads again &mdash; the equivalent of Burp's per-extension
  "Loaded" checkbox. The choice is remembered across restarts (in a small file
  alongside the extensions), and the change takes effect immediately. (Driven
  through the API for now &mdash; `POST /api/extensions/set-enabled {name, enabled}`,
  with every installed extension and its state in the snapshot; the checkbox in the
  Extensions view is the next step.)
- **Extensions get a built-in `nullock.utils` toolbox of codecs and hashes.** A
  JavaScript extension used to hand-roll base64, hex, and hashing in ES5. It can
  now call ready-made helpers &mdash; <code class="inline">nullock.utils.base64Encode/Decode</code>,
  <code class="inline">urlEncode/Decode</code>, <code class="inline">hexEncode/Decode</code>,
  <code class="inline">htmlEncode/Decode</code>, and <code class="inline">sha256</code> /
  <code class="inline">sha1</code> / <code class="inline">md5</code> (Burp's
  <code class="inline">api.utilities()</code> equivalent). They're plain text-in /
  text-out transforms with no permission needed, backed by a small unit-tested
  core so the results are correct and consistent. (A byte-array type and gzip
  helpers are still to come &mdash; JS has no native byte type, and extensions
  already receive decompressed response bodies.)
- **Extensions can read recent proxy history.** A JavaScript extension used to see
  only the single request/response it was handed at the moment it fired &mdash; to
  build up any picture of the traffic it had to accumulate that itself. It can now
  call <code class="inline">nullock.history(max)</code> to get the most recent proxy
  exchanges (Burp's <code class="inline">api.proxy().history()</code> equivalent),
  each an object with the method, host, port, path, URL, TLS flag, status code,
  response size, and timestamp &mdash; so a recon or scanning extension can look
  back over what's been captured. It needs no permission (it's the same traffic an
  <code class="inline">onResponse</code> handler already observes), the list is
  capped at the most recent entries, and it survives reloading the extension.
- **Out-of-band DNS interactions are now recorded and listable, and answered by
  record type.** A whole class of findings only ever trigger a DNS lookup &mdash;
  Log4Shell whose LDAP egress is firewalled, blind SSRF/SQLi/XXE where only name
  resolution escapes the target. Those callbacks were being counted and used to
  auto-confirm findings, but the raw interaction was thrown away: there was no way
  to inspect a DNS callback's queried name, source IP, or timing after the fact.
  The DNS sink now keeps each interaction in a ring buffer (like the HTTP sink) and
  exposes them at <code class="inline">/api/oast/dns/poll?since=&lt;id&gt;</code>,
  with its own cursor so you can page through new hits. Each record shows the full
  queried name, the resolver's source IP, the timing, and the record type that was
  asked for. And the responder now answers the type it was asked: an <code class="inline">A</code>
  query gets an A record, an <code class="inline">AAAA</code> query gets an AAAA
  record, and any other type gets a correct empty (NODATA) answer instead of the
  old always-an-A-record reply &mdash; while the interaction is logged regardless of
  type, so detection is unaffected.
- **Extensions can register a teardown callback that runs when they're unloaded.**
  A JavaScript extension can now call <code class="inline">nullock.onUnload(fn)</code>
  (or the Burp-compatible name <code class="inline">nullock.registerUnloadingHandler(fn)</code>)
  to register a function that fires once, on the engine thread, just before the
  extension is torn down &mdash; on a reload/uninstall and on app exit &mdash; while
  the JS engine is still alive. It's the hook a script needs to flush its own
  state, close a resource, or log that it stopped, instead of being cut off mid-run
  with no warning. Teardown callbacks need no permission (they clean up the script's
  own state and can't touch the wire), each is isolated so one throwing can't skip
  the others, and every registered handler is dropped when the engine is rebuilt so
  none leaks across a reload.
- **Match &amp; replace rules can match a literal string, not just a regex.** Each
  proxy match/replace rule now has a "literal" option: turn it on and the text you
  type in the *find* box is matched exactly, with characters like <code class="inline">.</code>,
  <code class="inline">*</code>, <code class="inline">?</code> and brackets treated
  as themselves instead of regex operators &mdash; so you no longer have to
  hand-escape a URL, a JSON snippet, or a version number. Regex is still the
  default. The setting saves with the rule. (Dedicated request-parameter-name and
  -value sections are still to come.)
- **Plaintext WebSocket (`ws://`) connections are now proxied properly.** An
  unencrypted WebSocket handshake used to be answered and then the connection was
  just dropped &mdash; the actual `ws://` messages never flowed, weren't logged,
  and couldn't be replayed. They're now relayed frame-by-frame through the same
  machinery as secure `wss://`, so plaintext WebSocket traffic shows up in the
  WebSocket history and can be inspected and resent like everything else.
- **Pre-add a host to the TLS pass-through list.** Nullock keeps a list of hosts
  it won't intercept &mdash; it tunnels their TLS straight through untouched. Until
  now that list only filled itself in *after* a host's handshake failed, so a
  certificate-pinned app (many mobile and desktop apps) had to break once before
  it was left alone. You can now add a host to that list up front, so it's tunnelled
  cleanly from the very first connection. Combined with the per-host "un-bypass"
  added earlier, the pass-through list is now fully hand-manageable. (Wildcards and
  IP-range entries are still to come.)
- **Content discovery can sweep file extensions.** Point it at a wordlist and a
  set of extensions (`.php`, `.bak`, `.old`, `.zip`&hellip;) and each word is now
  probed both as-is and with every extension appended &mdash; the classic
  backup-file sweep (`config` &rarr; `config.php`, `config.bak`, &hellip;). Before,
  every combination had to be pre-expanded into the wordlist by hand, which blew
  through the request cap; now the expansion happens server-side and the cap
  applies to the real total. (The extensions field in the discovery UI is the
  remaining step; drive it via the API for now.)
- **Optionally log out-of-scope traffic (the "browse, then scope, then review"
  loop).** Nullock filters out-of-scope traffic out of history, which is great for
  privacy but means anything you browsed *before* narrowing your scope was gone
  for good. A new proxy switch lets you keep it: turn on "log out-of-scope
  traffic" and requests to hosts outside your scope are retained in history and
  searchable, so you can browse broadly, decide scope afterwards, and still review
  what you already captured (Burp's log-everything behaviour). It stays **off by
  default** &mdash; the privacy-preserving choice &mdash; and applies to plain
  HTTP; an out-of-scope HTTPS host is still passed through opaquely with nothing
  to decrypt. (The at-the-moment "stop logging out-of-scope?" prompt and a
  per-row in/out-of-scope marker are still to come.)
- **Search gains case-sensitivity and a negative match.** Two Burp-parity
  modifiers on the search endpoint: `case=sensitive` makes the regex
  case-sensitive (it defaults to insensitive as before), and `negate=1` inverts
  the match to return the items that do **not** contain the pattern &mdash; the
  fast way to answer "which requests are *missing* this header/token?" across
  captured traffic. Negate works across every search source and shares the same
  regex-safety limits. (Scoping a search to a single site-map branch is still to
  come.)
- **All 50 teaching labs now have a real submit-flag success-check.** Labs
  41-50 (OAuth redirect_uri theft, credentials-in-URL/Referer leakage, XXE,
  CRLF injection/response splitting, dangerous HTTP methods, verb tampering,
  cache poisoning, sensitive file exposure, robots/sitemap disclosure,
  predictable session tokens) each gain a `/flag` endpoint that only returns
  the flag once the underlying bug was genuinely exploited server-side —
  e.g. lab 41 requires an auth code actually issued to a redirect_uri outside
  the client's registered origin, lab 44 requires the injected CRLF payload
  to land as a real second response header, lab 50 requires a session id
  that was predicted, not one the solver ever logged in for — matching the
  same "prove the exploit worked, don't just visit the page" bar as labs
  1-40's earlier flag rollout. Completes flag coverage for all 50 labs on
  the "Labs as TryHackMe/HackTheBox scenarios" roadmap item; XP/tracks and
  in-app (desktop) wiring remain open.
- **Search now spans Repeater and issues, not just proxy history.** The search
  endpoint only ever scanned captured proxy traffic, so a value sitting in a
  Repeater tab you were hand-testing, or in a finding the scanner raised, was
  invisible. It now searches those too: every result is tagged with the tool it
  came from (`proxy`, `repeater`, `issue`), Repeater request/response bodies
  honour the same request/response filter as history, and issues are matched on
  their summary, evidence, URL, host and kind. The same regex-safety limits and
  the single wall-clock budget cover every source, so a global search can't run
  away. (Intruder results and the site-map are still to be wired in.)
- **Comparer handles bigger, lopsided inputs.** The diff was capped at a flat
  2000 tokens per side, so comparing a short blob against a full-page response
  clipped the long side immediately even though the short side was tiny. The cap
  is now an adaptive *area* budget: a side that fits is kept whole and only an
  oversized side is trimmed, so a short-vs-long compare (e.g. a one-line injected
  value against a 30 KB response) now diffs the long side in full, and two
  moderately large responses compare at up to ~4000 tokens each instead of 2000.
  (Truly huge symmetric compares still clip &mdash; lifting that ceiling further
  needs the diff moved off the request thread, which is the remaining step.)
- **HTTPS interception now works against bare IP-address targets.** Proxying an
  `https://192.168.x.x/` or `https://10.x/` box &mdash; routine on internal
  engagements &mdash; used to fail: the forged certificate always carried a
  DNS-type name, which every modern client rejects for an IP host, and the failed
  handshake then permanently blocklisted the target. The forged leaf for an IPv4
  literal now carries a proper IP-address SAN, so a verifying client accepts it
  and interception just works. (Paired with the per-host **unblock** added
  alongside the invalid-cert work, a host blocked by the old behaviour is easy to
  recover.) IPv6-literal targets and multi/wildcard SANs are still to come.
- **Intruder: "Recursive grep" payload type &mdash; walk a token across requests.**
  Instead of a fixed wordlist, each request's payload is now the value pulled out
  of the *previous* response by the grep-extract rule &mdash; so an anti-CSRF
  token, a one-time nonce, or a sequential id that changes on every response can
  be chained forward across a run. You set an initial payload for the first
  request and how many requests to send; the run is serial (each depends on the
  one before) and stops early if a response has nothing to extract. This is the
  classic way to brute-force a form protected by a per-request token, or to walk a
  server-side state machine. Configured through the API for now
  (`recursiveGrep` / `recursiveGrepSeed` / `recursiveGrepCount` on
  `/api/intruder/set`, reusing the grep-extract rule as the payload source);
  verified end-to-end against a chaining server. (The payload-type selector in the
  Intruder UI and save/resume of a recursive attack are still to come.)
- **Intercept a target with an invalid TLS certificate (per-host opt-in).** A
  staging box with a self-signed or expired cert used to be un-interceptable
  &mdash; the upstream handshake failed and, worse, one attempt permanently
  blocklisted the host. You can now add a specific `host:port` to an
  accept-invalid-cert list and Nullock will proceed against that origin's bad
  cert, the way Burp does &mdash; but scoped to hosts you name, not a blanket
  "trust every bad cert" switch that would let an attacker's cert ride through
  for a host you never meant to relax. It stays safe in the ways that matter:
  only benign validation errors (self-signed, expired, name-mismatch, unknown
  issuer) are waived; a certificate the TLS stack flags as **blacklisted or
  revoked still fails closed**; the list defaults to empty and is saved per
  project (a relaxed posture never silently follows you into the next
  engagement); and every accepted cert is recorded with its **SHA-256
  fingerprint** and a console warning so you can spot an unexpected one. Fixing
  this also fixed the root-cause blocklist bug: a cert failure no longer
  permanently blocklists a host, and there's a new per-host **unblock** for hosts
  blocked for other reasons. Design hardened by a 4-agent adversarial review;
  verified with mutation-tested unit cases and an end-to-end test against a real
  self-signed origin. (Per-history-row cert annotations and fingerprint pinning
  are still to come.)
- **Repeater now shows response time and size.** Every Repeater send records how
  long the round-trip took (in milliseconds) and how many bytes came back, so the
  signal that matters for blind SQL injection, blind command injection and race
  work &mdash; *how long did it take* &mdash; is right there instead of invisible.
  The timer is measured around the actual network round-trip (before the response
  is decoded or formatted, so it reflects the wire, not local work) and follows a
  redirect chain if you have that on; the values are kept per tab, saved with each
  prior send in the tab's history, and cleared when you clear the tab. (Exposed on
  the backend + snapshot now; the render in the Repeater pane is the remaining UI
  bit.)
- **Proxy: auto-update Content-Length when you edit an intercepted request.**
  Editing an intercepted request's body used to leave a stale `Content-Length`,
  so the forwarded request was truncated or the origin hung with no hint why.
  Now, when you edit a **request** in the intercept editor, its `Content-Length`
  is recomputed to match the new body before it goes upstream (Burp's on-by-
  default behaviour), with an **Update Content-Length** checkbox right there in
  the Intercept tab's toggle bar to turn it off; the toggle is saved per project
  so a posture you turned off isn't silently re-armed on reopen. It's deliberately **surgical**, not the request-hardening
  `normalizeContentLength` the chain runner uses: a `Transfer-Encoding: chunked`
  or duplicate-`Content-Length` request is forwarded **verbatim** even with the
  toggle on, so a smuggling probe you're intentionally sending survives; only a
  single, unambiguous `Content-Length` value is rewritten, and the header name
  and every line terminator are preserved. Design hardened by a 4-agent
  adversarial review; verified with mutation-tested unit cases plus an
  end-to-end pass through the live proxy. (Response-side editing is unchanged for
  now &mdash; a HEAD/204/304 response legitimately carries a `Content-Length`
  with an empty body, so recomputing it there needs the paired request method the
  intercept layer can't yet see; tracked as the remainder.)
- **The captured cookie jar persists across restart.** With the session rules
  already persisting, the session **cookie jar** now saves too &mdash; the
  per-host cookies the proxy captured are written into the project file when you
  close or switch projects and restored when you reopen, so an authenticated
  session survives a restart instead of re-logging-in. Crucially, an **expired**
  cookie (a logged-out or timed-out token) is dropped on restore rather than
  replayed, so a stale session is never resurrected. The cookie&harr;JSON
  serializer round-trips the resolved lifetime exactly (a post-2038 expiry keeps
  full precision) and is unit-tested + mutation-proven; verified end-to-end
  (capture &rarr; save on project switch &rarr; restore with the expired cookie
  dropped). Completes "cookie jar + session rules persist across restarts".
- **Session-handling rules survive a restart.** Your session rules (grab a value
  from a response, inject it as `{{var}}` into later requests &mdash; CSRF-token
  refresh, JWT re-injection) were rebuilt from scratch every session. They now
  save into the project file and restore when the project reopens, per project so
  one engagement's rules never bleed into another's. The rule &harr; JSON
  serializer is shared between `/api/session-rules`, the snapshot, and the on-disk
  form, so the three can't drift.
- **Issue triage: override severity + soft-delete a finding.** Building on the
  false-positive marking, you can now also **override a finding's severity** (talk
  a scary "high" down to "low" when you've judged it, via `/api/findings/set-severity`)
  and **soft-delete** a finding to get it out of the list (`/api/findings/delete`).
  Both persist with the project and are reversible with no re-scan &mdash; the marks
  live in the project file keyed by finding identity and are applied at display time,
  so clearing an override or un-deleting brings the finding back exactly as the
  scanner found it. The snapshot carries the effective (possibly-overridden) severity
  plus a `deleted` flag per finding. Pure logic, unit-tested + mutation-proven.
  Completes the issue-lifecycle triage (false-positive / severity / delete).
- **Advanced scope control (protocol / host / port / file rules).** Scope was a
  host-glob include/exclude list only. You can now add precise include/exclude
  **rules** &mdash; per rule: protocol (any/http/https), a host regex, a port
  (exact or range), and a file/path regex &mdash; via `/api/scope/advanced`, so
  "everything under `app.example.com` **except** `/admin`" or "only port 8443" is
  finally expressible. The design was hardened against the ways a scope feature
  goes wrong in a security tool: it **composes** with the existing host-glob scope
  rather than replacing it (with no advanced rule the decision is byte-identical to
  before, and a lone exclude rule can never silently widen scope to everything);
  deny always wins across both layers; the proxy matches the **full URL** (so a
  path/port exclude actually filters), while tool gates that only know the host
  **fail closed** (an exclude for a host blocks it rather than firing an attack the
  rule forbade); user regex is validated + size-capped at set time and matched
  **outside** the scope lock so a catastrophic pattern can't stall every connection;
  and port is a numeric range, not a regex (so `443` can't match `8443`). Rules
  persist in the project file. The whole decision core is pure, unit-tested (42
  cases across the full adversarial matrix) and mutation-proven; verified e2e (an
  exclude on `/admin` filters it in the proxy while `/home` passes, and it survives
  restart). (The advanced-scope editor UI is the remaining follow-on.)
- **Content discovery runs concurrently (thread + throttle controls).** The
  wordlist brute-force fired one request at a time, so a real wordlist crawled.
  It now fans the probes across a bounded pool &mdash; `concurrency` (1&ndash;64,
  default 10) and an optional inter-dispatch `throttleMs` on `/api/content/discover`.
  Calibration stays serial and the detection logic is untouched, so results are
  **identical** to the old serial run (each path is classified against the same
  soft-404 profile, order-independent) &mdash; just far faster. Verified e2e: the
  same hit set serial vs. concurrent, and ~4&times; faster wall-clock at
  concurrency 10.
- **Export HAR: include unredacted auth material.** The Export HAR button
  (Settings' Project card) redacted `Authorization`/`Cookie`/etc by default
  with no way to opt out from the GUI, even though the backend already
  accepted a `redact:false` override on `/api/har/export`. A new checkbox
  next to the button lets you export the full, unredacted HAR when you need
  to hand a colleague something that reproduces the bug end to end.
- **Repeater: Change request method / Change body encoding.** Two new buttons
  in the Repeater request pane &mdash; ⇄ METHOD toggles GET/POST, moving params
  between the query string and an `application/x-www-form-urlencoded` body;
  ⇄ ENCODING converts that body to `multipart/form-data` and back. Both
  recompute `Content-Type`/`Content-Length` so the edited request stays
  well-formed &mdash; a first-move test for HPP, CSRF, and upload-parser/WAF
  bypass bugs that previously meant hand-editing raw bytes. Pure client-side
  text transform, dispatched through the same edit path a hand edit uses.
- **Triage scanner findings: mark false positives + suppress issue kinds.** Issue
  triage was all-or-nothing (clear everything). You can now mark an individual
  finding as a **false positive** (`/api/findings/mark`) and **suppress an entire
  issue kind** so it stops cluttering the list (`/api/findings/suppress-kind`).
  Both survive restart and are reversible with no re-scan: because findings persist
  append-only, the marks live in the project file keyed by finding identity / kind
  and are applied at *display* time, so un-marking a finding or un-suppressing a
  kind brings it right back. The snapshot now carries a `falsePositive` and
  `suppressed` flag per finding plus the `suppressedKinds` list, so the UI can dim
  or hide them and offer an undo. The identity key matches the scanner's dedup key
  exactly (unit-tested + mutation-proven). (The triage buttons in the Issues UI are
  the remaining follow-on.)
- **Intruder can follow redirects too.** The same follow-redirect engine now runs
  in Intruder: with `followRedirects` set (never / on-site / in-scope / always,
  plus `processCookies`), each fired payload's request follows its 3xx chain and
  the recorded row &mdash; status, length, and every Grep column &mdash; reflects
  the *final* page it lands on, so a bruteforce behind a login/redirect grades
  against real content instead of a wall of 302s. Set via `/api/intruder/set`.
  Reuses the shared, mutation-proven `redirect_logic`; verified e2e (an attack
  payload that 302-chains is graded on the final `200`).
- **Repeater can follow redirects.** A 3xx used to leave you copying the
  `Location` into a new tab and rebuilding the cookie jar by hand &mdash; on every
  login and OAuth flow. Repeater now optionally follows redirects after a send,
  with Burp's four modes (never / on-site only / in-scope only / always) and
  "Process cookies in redirections": it resolves each `Location` (relative or
  absolute), picks the right method (a `POST` becomes `GET` on a 301/302/303,
  stays `POST` on a 307/308), threads the original request's cookies plus every
  `Set-Cookie` along the chain, and shows the final response with a note of how
  many hops it followed (capped so a redirect loop terminates). Configurable via
  `/api/repeater/set` (`followRedirects` 0&ndash;3, `processCookies`). The whole
  decision core &mdash; status detection, URL resolution, method/body semantics,
  the follow policy, cookie threading &mdash; is pure, unit-tested and
  mutation-proven, and it's verified end-to-end (a `/a`&rarr;`/b`&rarr;`/c` 302
  chain is followed to the final page with the session cookie carried through).
  Shared logic, so Intruder can reuse it next.
- **Redirect-following is now a GUI control, not just an API call.** Both
  Repeater and Intruder gain a FOLLOW selector (never / on-site / in-scope /
  always) and a COOKIES checkbox right in their target/settings row, wired to
  the `followRedirects`/`processCookies` settings above via the existing
  `repeater-set`/`intruder-set` actions &mdash; no more driving the follow-redirect
  engine by hand-crafted `POST` calls. The backend snapshot now serializes both
  fields back to the GUI so the controls reflect live state after a reload.
- **Intruder's Resend now follows redirects too.** Resend (re-firing a single
  completed attack row) used to build its own request/response path with no
  `redirect_logic` involvement, so a resent row's grade could disagree with the
  original attack pass. Resend now runs the same chain-follow block as the
  attack-fire path, off the same `followRedirects`/`processCookies` setting
  &mdash; a resent row grades against the same final page a first-pass fired
  row does.
- **Sequencer live capture: harvest a token corpus automatically.** The Sequencer
  could only score a corpus you assembled yourself. A new background engine now
  fires the *same* request N times and pulls one token out of each response
  (`/api/sequencer/capture/start` + `/stop` + `/clear` + `/tokens`), then runs the
  existing randomness analysis over what it collected. Token extraction reuses the
  chain/session vocabulary — cookie / header / json-path / regex — over the
  **decoded** body (a gzip response no longer silently yields nothing), and never
  sanitizes the value so the entropy it measures is the token's real bytes. Because
  it *generates* traffic (unlike the passive proxy) it is safety-gated: it refuses
  to run unless the target is in a **non-empty engagement scope**, hard-caps the
  shot count, paces between shots (honoring a 429 `Retry-After`, bounded +
  interruptible), and trips a circuit breaker after a run of failures. A constant
  or too-small corpus is reported as exactly that — "captured value is constant …
  not a rotating token" — instead of being mis-scored as a guessable RNG. All the
  decision logic (extraction, clamps, shot classification, backoff parse, corpus
  verdict, scope predicate) is pure, unit-tested, and mutation-proven; the engine
  is verified end-to-end (rotating token → 30 distinct → "looks-random"; constant
  token → verdict guard; scope refusal; stop mid-capture). Closes the launch
  blocker "Sequencer has no live capture." (The Live Capture UI panel — request
  template, extract dropdown, progress bar — is the remaining follow-on; drive it
  today via the API.)
- **WebSockets tab.** A dedicated WEBSOCKETS tab groups captured WS traffic
  into a per-connection (host:port) list, with real per-message columns —
  direction, type (text/binary/close/ping/pong, deflate/continued flags
  decoded out of the synthetic history-row path), and length — plus
  direction/type filters and a per-message free-text comment
  (localStorage-persisted). Selecting a message reuses the Proxy tab's
  DetailPane, so Raw/Headers/Body/Hex/Inspector and every Send-to-* pivot
  work the same as HTTP history. No backend change — reads the same
  NL.rows entries the Proxy tab already showed as pseudo-HTTP WS↑/WS↓ rows.
  Left honestly partial: capture is still TLS-MITM-leg-only (a plaintext
  ws:// tunnel is never relayed), and two concurrent tunnels to the same
  host:port share one connection bucket since a history row carries no
  per-tunnel session id.
- **Send to Sequencer.** Proxy history's detail pane and Repeater's request/
  response panes gain a SEQUENCER/SEQ button: select a token substring (a
  session cookie, a CSRF token, a reset-URL token) and send it straight into
  Sequencer's manual-load corpus, switching tabs automatically. Repeatable
  across several captures to build up a real sample set without hand
  copy-pasting into the Sequencer tab. No backend change — a new client-side
  token inbox feeding the existing manual-load textarea.
- **Session rules: per-tool scope checkboxes in the editor UI.** The Sessions
  tab's rule editor gets a Proxy/Repeater/Intruder/Scanner checkbox row bound
  to each rule's `tools` bitmask (Burp's "Tools scope"), plus a per-rule scope
  summary in the rule list. No backend change — the `tools` field already
  round-tripped through `/api/session-rules`; this closes the editor-UI half
  of that gap. Enforcement stays as-is: Proxy, Repeater, and Intruder sends
  already honor a rule's scope; the Scanner checkbox is offered and stored but
  not yet enforced by any call site, and chain-runner/sequencer/extender
  scopes remain unbuilt.
- **Repeater unpacks gzip/deflate response bodies.** `HttpClient::send` (the
  transport Repeater and the detection-template engine both use) now decodes a
  `Content-Encoding: gzip`/`x-gzip`/`deflate` response body the same way the
  MITM proxy path already did, via the existing `decodeContentEncoding` helper.
  Repeater's response pane swaps the decoded body in for what used to render as
  binary mojibake (the header block, including the `Content-Encoding` header
  itself, is shown verbatim; the wire bytes on disk/in history are untouched).
  As a side effect, the detection-template engine's body-match evaluation
  (`/api/template/run`), which reads the same `bodyForInspection()` accessor,
  now also actually sees decoded bytes instead of silently matching against
  compressed ones.
- **Session macros: store, run, and auto-re-authenticate (login-macro engine +
  validity check).** Session handling now has named login macros: save a recorded
  login sequence via `/api/session-macros`, run one on demand with
  `/api/session-macros/run`, and — the validity check — attach a logged-out
  condition (a status list and/or a response-body regex) so that when a response
  to the macro's host matches it, the macro **re-runs automatically** and
  re-acquires the session. The re-auth is async (never blocks the proxy worker on
  login I/O) and loop-guarded: an in-flight lock plus a per-host cooldown, and the
  macro's own requests use the chain runner's client (not the proxy) so they can't
  re-trigger — a permanently-failing login can't hammer the target. The logged-out
  predicate is unit-tested + mutation-proven. Closes "no check-session-is-valid"
  and completes the session login-macro engine. (The visual macro editor UI is
  the remaining follow-on.)
- **Session login macros persist across restart.** A saved login macro (its
  recorded steps and its logged-out re-auth condition) now serializes into the
  project file under `sessionMacros` and is restored when the project reopens, so
  the login sequence and its auto-re-auth survive a restart instead of being
  re-entered every session. The macro &harr; JSON serializer is shared between the
  `/api/session-macros` endpoint and the on-disk form, so the two can't drift.
  (The cookie jar and the session rules themselves still don't persist — tracked
  separately.)
- **Turn a recorded login sequence into a live session (macro → session bridge).**
  A recorded chain (macro) can now feed the session variable bag: `POST
  /api/chain/run` with a `sessionHost` runs the macro and merges the values it
  extracts — a fresh CSRF token, a bearer token, a session cookie — into that
  host's session-rule variables, so the matching session rules then inject the
  acquired token into subsequent requests. That closes the loop from "record a
  login sequence" (the new recorder) to "stay authenticated" without hand-copying
  tokens. The auto-trigger that detects a logged-out response and re-runs the
  macro on its own is the next step. Part of the launch blocker "no
  session-acquisition macro".
- **Session-handling rules can be scoped to tools (foundation).** A session rule
  (auto-inject a captured token/cookie into matching requests) now carries a
  `tools` scope — proxy / repeater / intruder / scanner — so it can be limited to,
  or excluded from, specific tools. The scoping predicate is pure, unit-tested and
  mutation-proven, and the scope round-trips through `/api/session-rules`. Existing
  rules are unchanged (an unset scope means all tools). **Repeater and Intruder
  now apply scoped rules to their sends** — only rewriting the bytes when a rule
  actually fires, so a raw send no rule touches goes on the wire byte-for-byte.
  The per-tool editor checkboxes (ui-v2) are the remaining follow-on. Part of the
  launch blocker "no tools-scope on session rules".
- **Point the OAST / Collaborator at a hosted sink (client mode).** The out-of-band
  interaction sink was in-process only, so OOB detection (blind SSRF, RCE, XXE,
  log4shell) only worked against targets that could reach your own machine.
  `--oast-remote=http://host:adminPort --oast-remote-key=KEY` (or the matching env
  vars) now points the app at a hosted `nullock-oast`: mint proxies to its
  `POST /mint` so callback URLs carry the sink's public host, and a poll loop pulls
  its `GET /poll` and feeds hits through the same correlator — so every
  `/api/oast/*` path and the auto-confirmation of findings work unchanged. Falls
  back to the local sink if the remote is unreachable. Verified end-to-end (mint →
  real callback on the remote → hit polled back into the app). Closes the launch
  blocker "Collaborator is loopback-only / OOB doesn't work out of the box".
- **Repeater keeps a per-tab send history.** Each Repeater tab now records every
  send (request, response, status, timestamp) in a capped per-tab list, exposed in
  the snapshot and re-loadable via `/api/repeater/history/load` — so you can
  navigate back through what you sent in a tab, compare, and re-load a prior
  request. Session-only (kept out of the project file to avoid bloating it with
  response bodies). Closes the launch blocker "no per-tab request history".
- **Record a Repeater chain from captured traffic.** `ChainRunner` could replay a
  hand-defined request sequence, but nothing captured one from real traffic. New
  `/api/chain/record` takes selected history row IDs and emits a replayable macro
  (the `/api/chain/run` step shape — one step per request, name derived from the
  request line), ready to POST straight back to run, or to edit in the `{{var}}`
  extractions that thread a token from one response into the next request. The
  step-builder is a pure function with unit tests, mutation-proven on the name
  derivation. (Session-acquisition auto-wiring — pushing recorded values into the
  cookie jar — is the noted follow-up.) Closes the launch blocker "no macro
  recorder".
- **Proxy intercept rules — hold only the requests/responses you care about.**
  Interception was global all-or-nothing: turn it on and every in-scope message
  parks, static assets included. It's now driven by a rule list (Burp's "Intercept
  Client/Server Requests"): each rule matches on method, URL regex, host glob, file
  extension, content-type, status code, or a header name, combined with And/Or and
  a per-rule negate — the message is held only if the rule fold says so (an empty
  list still holds everything). Rules are settable via `/api/intercept/rules` and
  persist in the project file (survive restart, verified). The decision engine is a
  pure predicate with 63 unit cases, mutation-proven on the negate + And-fold. A
  RULES panel in the Intercept tab now edits the list live — add/edit/reorder/
  toggle/delete, matching this exact wire contract. Closes the launch blocker
  "there are no intercept rules".
- **Proxy can bind off-loopback for VM / phone / container testing.** The proxy
  listener was hardwired to `127.0.0.1`, so another machine's browser couldn't be
  pointed at it. `--proxy-bind=ADDR` (or `NULLOCK_PROXY_BIND`) now binds it to any
  interface. Because an off-loopback intercepting proxy exposes a cert-forging
  MITM (and an open relay) to the whole LAN, a non-loopback bind is refused unless
  you also pass `--proxy-bind-insecure` to acknowledge, and it prints a loud
  warning banner. The stop/start toggle now re-listens on the same bind
  (`ProxyServer::restart()`) instead of silently reverting to `127.0.0.1:8080` —
  which also fixes a pre-existing bug where toggling reset a custom `--proxy-port`.
  Closes the launch blocker "the listener cannot bind to anything but loopback".
- **Repeater tabs persist per project and restore on reopen.** Staged Repeater
  requests were wiped on every project switch and lost on close. They're now saved
  into the project file (`project.json` under `repeater`) and restored when the
  project reopens — while preserving strict engagement isolation: the outgoing
  project's tabs are saved to *its own* file *before* the switch wipes them, and
  the incoming project's are loaded after, so one client's staged request (and its
  `Authorization` header) never surfaces in another's project. Response bodies are
  omitted from the saved state to keep the project file small (re-sending
  reproduces them). Verified by a smoke test that stages a canary auth header,
  switches projects (asserts no leak), then switches back (asserts restored).
  Closes the launch blocker "a project switch wipes your tabs".
- **Repeater recomputes Content-Length automatically (Burp's "Update
  Content-Length", on by default).** Editing a request body in Repeater left a
  stale `Content-Length` on the wire — the length had to be hand-fixed on every
  edit. Repeater now recomputes it from the actual body before each send, reusing
  the chain runner's audited helper (which also collapses a duplicate
  `Content-Length` and drops it under `Transfer-Encoding: chunked` — both
  request-smuggling vectors). It's a toggle (`autoContentLength`, settable via
  `/api/repeater/set`, surfaced in the state snapshot) that defaults **on**; turn
  it **off** to send the bytes verbatim for a deliberately-malformed CL/TE
  smuggling test, preserving the raw-send capability a security tool needs.
  Closes the launch blocker "no Content-Length auto-update".
- **Scan findings now persist across app close and project reopen.** Passive-scan
  findings were held in memory only — they vanished when the app closed and were
  wiped on every project switch, so an engagement's findings evaporated. Each
  finding is now appended to `<project>/findings.ndjson` at discovery time
  (append-on-report, so a crash still preserves it; deduped by the same
  kind+host+url+summary identity key the baseline uses, so a re-discovered or
  restored finding is never written twice), and streamed back into the findings
  panel when the project is (re)opened — preserving each finding's original
  discovery timestamp, enrichment (CWE/OWASP/CVSS/compliance/fix), and history
  rowId so click-to-jump still lands on the right request. Adds a pure
  `FindingSerial` JSON round-trip module with its own unit test
  (`ctest -R finding_serial`, mutation-proven on the `ts` and `compliance`
  fields); restore replays through the scanner's public surface via a new
  `ingestFinding` (no re-enrich, no re-persist), and discovery is captured via a
  new `findingAdded(const Finding&)` signal. Closes the top launch blocker —
  "scan issues are not persisted in the project file; findings vanish on reopen".
- **Intruder "ECB block shuffler" payload type.** Splits a hex-encoded ciphertext
  into `blockSize`-byte blocks and emits the block-shuffled variants (rendered
  back to hex) — the classic attack against ECB-mode tokens, where permuting
  ciphertext blocks permutes the decrypted plaintext blocks. It emits the complete
  block-permutation set (lexicographic order), deduplicated (ECB repeats blocks)
  and capped; non-hex or non-block-aligned input yields nothing. Mutation-proven
  (the block-alignment guard and the dedup each fail their cases when broken).
  Closes roadmap parity item "Payload type: ECB block shuffler".
- **Intruder regex match/replace processing rule.** The payload-processing chain
  had only a literal `match-replace`; it now also offers `regex-replace`, which
  matches a regular expression and replaces every occurrence, with Burp-style
  back-references in the replacement (`$0` whole match, `$1`–`$9` captured
  groups, `$$` a literal `$`) — closing the defining gap of Burp's match/replace
  rule. An invalid pattern or missing separator leaves the payload unchanged.
  Mutation-proven (the capture-group expansion and the global iteration each fail
  their cases when broken). Closes roadmap parity item "Processing rule:
  Match/replace".
- **Intruder "Modify case" processing rule gains the propername variants.** The
  payload-processing chain had only `uppercase` / `lowercase`; it now also offers
  `propername` (Titlecase — upper-case the first character, lower the rest) and
  `propername-keep` (upper-case the first character, keep the rest), matching
  Burp's Case-modification rule. Both are code-point-safe (a leading non-BMP
  glyph is handled whole) and reuse the same proper-case semantics as the
  `casemod` generator. Mutation-proven. Closes roadmap parity item "Processing
  rule: Modify case".
- **Intruder "Illegal Unicode" payload type.** Generates the overlong UTF-8
  encodings of a target character at each byte length from 2 to 6 — the classic
  WAF / path-traversal bypass, e.g. `/` → `%C0%AF`, `%E0%80%AF`,
  `%F0%80%80%AF`, … Output is hex, optionally `%`-prefixed per byte and
  upper/lower-cased; byte lengths are clamped to the legal 2–6 range and a length
  that can't represent the code point is skipped. Semantics confirmed against the
  PortSwigger docs; pure + mutation-proven (the lead-byte prefix and the
  continuation-byte marker each fail their cases when broken). Closes roadmap
  parity item "Payload type: Illegal Unicode".
- **Intruder "Username generator" payload type.** Derives candidate usernames
  from a full name or email address using common schemes (first/last,
  concatenations, dot/underscore/hyphen separated, reversed order, and
  first/last-initial combinations) — e.g. `peter wiener` → `peterwiener`,
  `peter.wiener`, `wienerpeter`, `peterw`, `pwiener`, `p.wiener`, … An email uses
  its local part; output is lower-cased, deduplicated, and hard-capped. Pure +
  mutation-proven (the initial extraction and the email local-part handling each
  fail their cases when broken). Closes roadmap parity item "Payload type:
  Username generator".
- **Intruder "Substring" / "Reverse substring" payload-processing rules.** Two new
  processing ops matching Burp: `substring` extracts a slice from a 0-indexed
  start offset (plus optional length; omitted length runs to the end), and
  `reverse-substring` counts the end offset and length backwards from the end of
  the payload (verified against the PortSwigger definition). Both are code-point
  safe (a non-BMP glyph is never split) and fail safe — an out-of-range or
  malformed spec leaves the payload unchanged rather than dropping it from the
  run. Mutation-proven (the start offset and the reverse end-offset each fail
  their cases when broken). Closes roadmap parity item "Processing rule:
  Substring / Reverse substring".
- **Cookie jar respects cookie lifetime (Max-Age / Expires) — expired cookies are
  no longer replayed.** The jar stored `Expires` as an opaque string and ignored
  `Max-Age`, so an expired or logged-out cookie could be replayed forever. Now:
  `parseSetCookie` reads `Max-Age`; `resolveCookieExpiry` computes an absolute
  expiry at capture time with RFC 6265 §5.3 precedence (Max-Age wins; `Max-Age
  <= 0` or a past `Expires` is an immediate deletion); `parseCookieExpires`
  parses the HTTP-date (C-locale/UTC; unparseable → session cookie); and
  `cookieExpired` is the lifetime predicate (all pure + mutation-proven). This is
  now **enforced** in the session manager: a captured cookie's lifetime is
  resolved on receipt, an already-expired Set-Cookie deletes the stored cookie of
  that name (server-driven logout), and an expired cookie is never re-injected.
  Session vs. persistent cookies are distinguished in the store and surfaced
  (`persistent` / `expiresEpoch`) to the UI.
- **Intruder "Grep - Payloads" reflected-payload flagging.** Burp auto-flags a
  result row when one of its submitted payloads is reflected in the response;
  Nullock now does too, so you no longer hand-build a grep-match needle per
  payload. A new `IntruderGrep::payloadReflected` predicate does a **literal**
  substring test (a payload is data, not a pattern — `a.b` is reflected only by
  `a.b`, never `axb`; bounded to the same 256 KiB scan cap), wired into a
  per-row `reflected` flag/column that persists across save/resume. Enabled with
  `grepPayloads: true` on the intruder-set API; off by default. Mutation-proven
  (the literal-vs-regex behaviour and the case-sensitivity option each fail
  their cases when broken). Closes roadmap parity item "Grep - Payloads (flag
  reflected payloads)".
- **Intruder "URL-encode these characters" global safety net.** Burp applies an
  always-on payload encoder that percent-encodes a configured set of characters
  in every payload; Nullock now matches it. A new `url-encode-chars`
  payload-processing op encodes *only* the listed characters (code-point-safe:
  a multi-byte character encodes all of its UTF-8 bytes, and a non-target
  non-BMP glyph passes through without being split), and the Intruder appends it
  as the final step of every payload's processing chain when a global character
  set is configured (via `encodeChars` on the intruder-set API). Off by default
  (empty set) so existing attacks are byte-for-byte unchanged. Mutation-proven
  (the uppercase-hex formatting and the char-set membership each fail their
  cases when broken). Closes roadmap parity item "Payload encoding (global
  'URL-encode these characters')".
- **Labs get difficulty ratings and progressive hints.** The 50 teaching labs
  under `labs/` (docs/labs site) previously gave only a title, description, and
  full numbered walkthrough — no signal on how hard a bug is before you start,
  and no partial-credit path if you get stuck short of the full answer. Each lab
  now carries a curated Easy/Medium/Hard difficulty (reflected XSS/IDOR/broken-
  access-style bugs are Easy; JWT/SSRF/NoSQLi-style are Medium; SSTI/race-
  condition/deserialization/prototype-pollution/XXE/OAuth-state are Hard) shown
  as a badge on the catalog and detail pages, plus a difficulty filter alongside
  the existing category filter. Each lab also gets 3 hand-written progressive
  hints (a nudge, then a technique, then a near-payload) in a collapsible
  section above the full walkthrough. First installment on the "Labs as
  TryHackMe/HackTheBox scenarios" roadmap item — submit-flag/success-check
  landed separately (see above); XP/tracks and in-app (desktop) wiring
  remain open.

### Fixed
- **Creating a project from a template now applies the template's match &amp;
  replace rules.** A project template can ship a set of proxy match/replace rules
  (the OAuth-review template, for instance, carries a rule that flags an
  <code class="inline">/authorize</code> request missing its <code class="inline">state</code>
  parameter). Creating a project from a template applied its scope and notes but
  silently dropped the rules, so a template that promised them delivered none.
  They're now applied to the new project. (A template's <code class="inline">extensionsEnabled</code>
  list is still not enforced &mdash; extensions currently load globally rather than
  per-project, so there's no per-project set to write it into yet; the response
  echoes back what the template asked for.)
- **A session-handling rule that sets a fixed cookie/header/parameter value never
  fired.** A rule with a hard-coded value (e.g. "always add `X-Debug: 1`" or "set
  cookie `env=staging`" on this host) is purely static &mdash; it has no captured
  `{{variable}}` &mdash; yet the session engine bailed out entirely whenever the
  per-host variable bag was empty, so nothing was ever injected until some other
  rule happened to capture a value first. Static rules now fire regardless of what
  has been captured. As a matched safeguard, a rule whose own `{{variable}}` was
  never captured is now skipped individually (rather than injecting the raw
  literal `{{token}}` as a garbage value), so one un-resolved rule can't corrupt
  the request while the static rules alongside it still apply.
- **Comparer's proxy-history diff overlay could hang/OOM on a large response.**
  The DIFF-vs overlay's client-side line diff (`diffLines`, `ui-v2/proxy.jsx`)
  built an uncapped n×m LCS table — the same unbounded-input risk the backend
  Comparer engine (`compare.cpp`) already guards against with a 2000-token cap,
  but the JS engine had no equivalent limit. Now clips each side to 2000 lines
  (mirroring the backend's cap) and shows a TRUNCATED badge in the overlay
  header when either side is clipped.
- **`scanner_regression_test` failed to link on every CI runner (Linux and
  Windows) for four commits.** The session-rules Repeater-enforcement change
  (`SessionRules::applyToRequestBytes`) added the test target's first call
  path into `Proxy::serializeRequestForOrigin`, defined in `proxy_server.cpp`
  — pulling that whole translation unit, including its
  `ExtensionsApi::applyRequestMutation`/`applyResponseMutation` calls, into
  the link. `Tests/scanner_regression/CMakeLists.txt` didn't link the `APIs`
  library that defines them, so both linkers failed with two unresolved
  externals. Not flaky and not "transitive-link staleness" as an earlier
  commit message assumed — deterministic on a from-scratch CI build, which is
  all this repo's CI ever does (no ccache). Fix: link `APIs`, the same library
  `extensions_api_grant_test` already links standalone; safe here since `APIs`
  no longer links `Networking` (see `Src/Core/APIs/CMakeLists.txt`) and this
  target already links `FrontEndGUI` for the unrelated ProxyModel symbols
  Networking's Repeater/Intruder need.
- **Verbose-error detection no longer misses the two most common leaks.** The
  SQL/framework error detector was gated `400 <= status < 500`, so it missed a
  SQL error **echoed in a 200** (the app catches the DB exception and renders
  it) and a framework **DEBUG page on a 500** (Werkzeug/Symfony/Whoops). Widened
  with a **per-needle status policy** to avoid new false positives: the specific
  SQL-error signatures now flag on any status; framework debug-page markers flag
  on 4xx **and** 5xx; and the generic php `Warning:` / `Notice:` needles stay
  **4xx-only** (they appear in ordinary 200 copy like "Warning: low battery", so
  widening them would fire on innocuous pages). Locked with FP negatives (a 200
  saying "Warning: low battery" must not fire) and revert-proven (both the SQL
  widening and the php 4xx-only guard fail their cases when reverted).
- **Outbound-PII check no longer skips PUBLIC 172.x destinations.** The
  exfiltration gate treated any host matching `startsWith("172.")` as private,
  but RFC 1918 reserves only `172.16.0.0`–`172.31.255.255` (172.16/12). So SSN /
  card / phone / IBAN leaving in a request to a **public** 172.x host
  (172.0–15.x, 172.32–255.x — e.g. `172.200.1.1`) was silently not flagged. The
  gate now parses the second octet and treats only 172.16–31.x as private (a
  non-numeric second label like `172.example.com` is a hostname, not a private
  IP). Boundary cases (172.15/16/31/32) lock the range; proven necessary
  (restoring the old gate fails exactly the public-172 cases).
- **Django DEBUG page exposure is detected again (`stack-django` was a dead
  row).** Django renders its URLconf resolver on a **404** DEBUG page, not only
  on 5xx, but the stack-trace detector was gated `statusCode >= 500` — so the
  `stack-django` needle ("Django tried these URL patterns") never fired on the
  page where it actually appears, silently missing every `DEBUG=True`
  deployment. The gate now also admits a 404, but **only** the Django needle is
  eligible there; every other framework needle stays 5xx-only so an ordinary
  not-found page that merely quotes `java.lang.` / `at Object.` can't produce a
  false stack leak. Covered by a 404 positive and a Django-only gate negative;
  the fix is proven necessary (reverting the gate fails the 404 case).
- **Sequencer bit-level tests no longer mislabel or silently skip corpora.** The
  token→bytes decoder had two silent-wrong paths: an odd-length hex corpus failed
  the even-length gate, fell through, and was decoded *and labelled* base64
  (wrong bytes and wrong scheme); and a single non-conforming token (a truncated
  sample, a JWT's `.`) set the whole corpus to "not applicable", so 999 good
  tokens got zero bit-level analysis because of one bad one. The decoder now
  picks the scheme by charset **majority**, treats a hex-charset corpus as hex at
  any length (odd tokens left-padded to preserve the half-byte), and **skips**
  non-conforming tokens instead of aborting — reporting the skipped count
  (`bitLevel.skipped`) rather than dropping it silently. A genuinely mixed corpus
  still reports not-applicable. Mutation-tested (both fixes discriminate). Closes
  roadmap #152. (Residual, documented: a base32/alphanumeric corpus is still
  labelled "base64" — the bytes are analysed correctly, only the label is
  imprecise; Qt ships no base32 decoder.)
- **Site nav no longer drops links on secondary pages.** The hand-written
  pages (about, pricing, changelog, license, privacy, security, support,
  terms, and the docs landing) carried a stale nav missing the
  Extensions/Labs/Roadmap links, so those tabs "disappeared" once you left the
  homepage. All pages now expose the full section set; a whole-site check
  confirms 0 broken links and every page reaches all five sections.

### Security
- **Locked seven previously-untested leaked-secret detectors.** The passive
  scanner ships ten `leaked-*` credential patterns but only three (AWS key, GitHub
  PAT, Stripe) had a regression test — so a regex regression could have silently
  stopped detecting GitHub App, Slack, SendGrid, Mapbox, Google API, PEM private
  key, or AWS secret leaks. Added positive detection cases for all seven (built at
  runtime from fragments so no literal secret sits in the repo); mutation-proven.
- **Locked all seven subdomain-takeover fingerprints.** The passive scanner
  raises a HIGH `takeover-*` finding when a 404/503 body carries a vendor
  "unclaimed resource" error page (S3 `NoSuchBucket`, Heroku *No such app*,
  GitHub Pages, Azure *Web Site not found*, Fastly *unknown domain*, Shopify
  *shop unavailable*, Tumblr), but none had a positive test — a broken needle
  would have silently stopped flagging takeovers. Added one positive case per
  vendor, a 503-branch lock, and a status-gate negative (the same needle in a
  `200` body must **not** fire); mutation-proven (s3 + tumblr needles).
- **Locked all nine server-error stack-trace fingerprints.** A 5xx body
  leaking an internal stack trace (`stack-python`/`java`/`dotnet`/`php`/`ruby`/
  `node`/`rails`/`django`/`spring`) tells an attacker which framework and line
  numbers to target, but the family had no test. The needle table is scanned
  first-match-wins, so each positive fixture is crafted to carry exactly its own
  vendor needle and none listed above it — the cases now also pin the table
  ordering (a reorder that shadowed a later vendor would fail here). Added a
  status-gate negative (a stack trace quoted in a `200` body must **not** fire)
  and mutation-proved the python + spring needles. (Noted for follow-up: the
  `stack-django` needle appears on Django's DEBUG **404** page, but the gate is
  `>= 500` — a behaviour question tracked separately, not changed here.)
- **Locked the four remaining cloud-storage endpoint detectors.** Only
  `cloud-s3-bucket` had a test; `cloud-gcs-bucket`, `cloud-azure-blob`,
  `cloud-firebase`, and `cloud-firebase-storage` did not — a broken bucket-URL
  regex would have silently stopped surfacing exposed public storage. Added a
  positive per vendor plus two discriminating negatives: a GCS URL in a
  non-HTML (JSON) body must **not** fire (the detector is HTML-gated), and a
  suffix-append look-alike host (`storage.googleapis.com.evil.test`) must **not**
  fire (the regex requires the exact host followed by a path separator).
  Mutation-proven (gcs + azure regexes).
- **Locked the inline-JS DOM-XSS sink + credential-storage detectors.** The
  four `dom-*` sinks (`innerHTML <- location`, `eval/setTimeout(location…)`,
  `postMessage(_, '*')`, `eval(responseText)`) and `storage-of-secrets`
  (`localStorage.setItem('token'…)`) had no test — a broken regex would have
  silently stopped flagging client-side XSS sinks and credential-in-storage
  patterns. Added a positive per sink (each body carries exactly one pattern,
  pinning the first-match-wins table order) plus three precision negatives: the
  same sink in a non-HTML (`application/javascript`) body must **not** fire (the
  scan is HTML-gated), `postMessage` with an explicit origin must **not** fire
  (only the `'*'` wildcard does), and `innerHTML` set to a static string must
  **not** fire (the sink keys on a tainted source). Mutation-proven (innerHTML +
  eval-of-fetch regexes).
- **Locked the outbound-PII exfiltration detectors.** The defensive `pii-*`
  checks (`pii-ssn-outbound`, `pii-cc-outbound`, `pii-phone-us`, `pii-iban`)
  flag customer data leaving in a request to a *public* host, but only
  `pii-email-mass` had a test — a broken regex would have silently stopped
  flagging SSN/card/phone/IBAN exfiltration. Added a positive per class (the
  test PAN built from fragments so no card-shaped literal sits in the repo) plus
  three private-host-gate negatives: the same SSN to a `10.x` host, a
  `.internal` host, and a `172.200.x` host must **not** fire. The last also
  documents a known quirk — the gate uses `startsWith("172.")`, which
  over-broadly suppresses *public* 172.x too (only 172.16–31 are RFC-1918); the
  test locks current behaviour and flags it for a follow-up tightening.
  Mutation-proven (ssn + iban regexes).
- **Locked every verbose-error-leak needle — passive scanner detectors now
  fully covered.** The `verbose-sql-err` (6 needles), `verbose-php-err` (2), and
  `verbose-debug-page` (3) rows had no test — a typo in any one needle would have
  silently stopped flagging that leak. Added one 4xx-body positive per needle
  (each carrying only its own needle, pinning the case-sensitive first-match-wins
  table) plus two status-gate negatives: the same SQL error in a `200` body and
  in a `500` body must **not** fire (`verbose-*` only scans 4xx; 5xx is the
  stack-trace family's domain). Mutation-proven (ORA- + Werkzeug needles). With
  this, every kind emitted by `passive_scanner.cpp` has regression coverage.
  (Noted for follow-up: the 4xx-only gate misses the two most common cases — SQL
  errors echoed in a `200` and framework debug pages rendered on a `500`; a
  gate widening with FP analysis is tracked separately.)
- **Locked the JWT `analyze()` → `jwt-kid` emission.** `kidLooksRisky()` was
  directly unit-tested, but nothing asserted that `analyze()` actually turns a
  `kid` header into a `jwt-kid` finding at the right severity — a dropped emit,
  an inverted presence gate, or a backwards severity map (risky↔benign) would
  have passed the predicate tests yet silently broken the finding. Added
  analyze-level cases: a risky kid (path traversal) → `jwt-kid` at **medium**, a
  benign opaque kid → **info**, and no kid → no finding. Mutation-proven (the
  severity map and the emit id each break exactly the expected cases).
- **Locked five previously-untested security-header checks.** The header auditor
  emitted `xcto-missing` (X-Content-Type-Options), `hsts-missing`, `csp-missing`,
  `csp-report-only`, and `csp-unsafe-eval`, but no test asserted them — a
  regression silently dropping any would have gone unnoticed. Added discriminating
  positive/negative cases (mutation-proven: disabling the `xcto`/`hsts` emits now
  fails the suite).
- **Cookie jar no longer replays a Secure cookie over cleartext (or refuses it on
  a non-standard TLS port).** The session/cookie-jar auto-inject gate decided a
  Secure cookie's transport by a port heuristic (`port == 443`) instead of the
  actual connection encryption. That both *leaked* a captured Secure cookie onto a
  cleartext request that happened to use port 443 and *refused* to inject it over a
  genuine TLS connection on a non-standard port (e.g. 8443). `HttpRequest` now
  carries a real `tls` flag (set on the MITM'd HTTPS paths), and
  `injectableOverTransport(cookie, tls)` gates a Secure cookie strictly on TLS —
  fail-closed (an unknown transport never injects a Secure cookie). Mutation-tested.
  Fixes roadmap #165.

- **Header-audit redirect follower is now same-origin-only.** It previously
  gated redirects on hostname alone, so it would follow an `https→http` scheme
  downgrade or a port change and re-emit the captured `Cookie`/`Authorization`
  to that origin — over cleartext on a downgrade — while binding the new
  origin's verdicts to the original URL. It now requires an exact
  scheme+host+port match before following and never carries credentials across
  an origin change (`isSameOriginRedirect`, mutation-tested). Fixes finding #1
  of the multi-agent `Src/Core/Networking` security review.
- **JWT probe no longer reports false signature/algorithm bypasses on
  cookie-auth endpoints.** It stripped secondary credentials only on the
  no-token calibration shot, so a forged-token shot kept a carried session
  `Cookie` — a cookie-authenticated endpoint that ignores the JWT stayed
  authorized, and the (no-token denied / forged allowed) differential was
  misreported as a real bypass. It now strips every non-target credential on
  BOTH shots, leaving the injected JWT as the sole credential; the test that
  pinned the old behaviour is corrected. Fixes finding #2 of the review.

### Added
- **Cookie jar now captures the `Domain` attribute + RFC 6265 domain-matching
  (foundation for domain-scoped injection, #194).** The cookie-jar parser was
  dropping the `Domain` attribute entirely (only path/expires/httponly/secure/
  samesite were handled), so a `Domain=.example.com` cookie could never be scoped.
  `Set-Cookie` parsing now records the domain (lowercased, a single leading `.`
  stripped, empty ⇒ host-only), and a pure `domainMatches` predicate implements
  RFC 6265 §5.1.3 with a proper label boundary (`evil-example.com` does not match
  `example.com`) and IP-literal handling (exact-only). Unit- and mutation-tested.
  This is the foundation for #194 — wiring domain-aware, deterministic multi-host
  injection (plus the §5.3 Domain-vs-origin check) into `injectInto` remains.
- **Intruder "Bit flipper" generator (Burp parity).** A new `bitflip` payload
  type (`IntruderGenerators::bitFlip`) walks each byte of the base and emits one
  payload per bit position (LSB→MSB) with that single bit XOR-flipped — the
  standard fuzz for off-by-one parsers, checksum/MAC validators, and encoding
  edges. Output order and rendering match Burp exactly (`"ab"` → the 16 variants
  `` `b,cb,eb,ib,qb,Ab,!b,áb, ac,a`,af,aj,ar,aB,a",aâ``). Bounded at `kMaxCount`;
  wired into `/api/intruder/generate` + `types()`. Unit- and mutation-tested.
  Closes roadmap #35.
- **Intruder "Character substitution" generator (Burp parity).** A new `charsub`
  payload type (`IntruderGenerators::charSub`) takes a list of items and a
  character-substitution map (e.g. `e→3`, `t→7`) and, for each item, emits every
  combination of applying-or-not each substitutable position — all 2^k
  permutations (`peter` + `{e:3,t:7}` → the 8 leetspeak variants). Enumerated
  as a binary counter (leftmost position = LSB) to match Burp's order exactly;
  bounded at `kMaxCount`. Wired into `/api/intruder/generate` + `types()`. Unit-
  and mutation-tested. Closes roadmap #28 (which the audit mis-labelled
  "Character substring"; Burp's actual payload type is Character substitution).
- **Sequencer positional test now explains length-tolerance (Burp "Ignore token
  length differences").** The per-position (cross-sample) analysis needs a
  dominant token width and previously reported a bare `applicable:false` when it
  couldn't run — indistinguishable from a too-small corpus. The `positional`
  result now always carries `modalWidth`, `atModalWidth`, and `offWidth` (tokens
  excluded for not matching the modal width), plus a `skipReason`
  (`length-variance` / `too-few-tokens` / `too-few-at-width` / `tokens-too-short`)
  when it's skipped. So a variable-length corpus is now clearly flagged as such,
  and when the test does run the count of excluded off-width tokens is surfaced
  rather than silently dropped. Same applicable/gating behaviour as before;
  mutation-tested. Closes roadmap #144.
- **Intruder "Case modification" generator (Burp parity).** A new `casemod`
  payload type (`IntruderGenerators::caseMod`) takes a list of items and, for each,
  emits one payload per selected case option in canonical order — the five Burp
  options: No change, lower, upper, `Propername` (first letter upper, rest lower),
  and `ProperName` (first letter upper, rest unchanged) — for case-variant
  username/wordlist fuzzing. The two Proper modes are distinct exactly as the
  PortSwigger docs specify; the leading letter is upper-cased by code point
  (non-BMP safe). Wired into `/api/intruder/generate` + `types()`. Unit- and
  mutation-tested (the Propername-vs-ProperName distinction is locked). Closes #29.
- **Intruder "Character blocks" generator (Burp parity).** A new `blocks` payload
  type (`IntruderGenerators::charBlocks`) repeats a base string by a multiplier
  from min to max stepping by a step — one payload per multiplier (`base × k`),
  e.g. `"A"` × 1..3 → `A, AA, AAA` — for buffer-boundary / length-limit fuzzing.
  It multiplies (whole-repeat) the base, not truncate-to-length (verified against
  the PortSwigger docs). Bounded in count and total chars, and refuses to build a
  block that would breach the cap, so a huge multiplier can't OOM. Wired into
  `/api/intruder/generate` + `types()`. Unit- and mutation-tested. Closes #32.
- **Intruder "Character frobber" generator (Burp parity).** A new `frobber`
  payload type (`IntruderGenerators::frob`) walks a base string one position at a
  time, emitting one payload per position that is the whole base with exactly that
  character's code point incremented by +1 (Burp's frobber) — for probing
  off-by-one parsers, checksum/signature validators, and encoding edge cases. It
  increments by code point (not UTF-16 unit) and keeps every result a valid
  Unicode scalar (a bump into the surrogate range skips to U+E000, past U+10FFFF
  wraps to 0), and is bounded in both count and total char volume so a huge base
  can't OOM. Unit- and mutation-tested. Closes roadmap #34.
- **Intruder "Null payloads" generator (Burp parity).** A new `null` payload type
  (`IntruderGenerators::nullPayloads`) emits N empty payloads, filling a position
  with nothing so the base request is re-sent unchanged N times — the standard way
  to probe rate limits, race conditions, or non-deterministic responses. Capped at
  `kMaxCount`; wired into `/api/intruder/generate` + advertised by `types()`.
  Unit- and mutation-tested. Closes roadmap #33.
- **Intruder payload-processing now offers Decode rules (Burp "Decode" parity).**
  The rule dropdown (`/api/intruder/rule-ops`) previously advertised only encode
  and hash transforms — decode was deliberately hidden ("payloads are authored,
  not received"), but real payload lists arrive pre-encoded (base64 wordlists,
  URL/hex-encoded fuzz strings) and Burp offers decode rules for exactly that.
  The decode inverse of each advertised reversible encode — `base64-decode`,
  `base64url-decode`, `url-decode`, `hex-decode`, `html-decode` — is now offered.
  The ops already executed (they delegate to the Transcode workbench) and fail
  safe: a decode of non-decodable input is a no-op, so a payload never vanishes.
  Round-trips are unit- and mutation-tested. Closes roadmap #40.
- **Sequencer now detects WRAPPED counters.** The sequential/counter detector
  previously required a token to be numeric end-to-end, so a real-world wrapped
  counter — `sess_1001`, `user-42`, `id_007` — was reported "not sequential"
  (a false negative Burp's encoding-agnostic low-entropy inference still caught).
  A shared non-numeric wrapper is now stripped before the counter tests, so
  prefixed/suffixed decimal & hex counters are flagged with their true step,
  while a bare stepped counter (`100,200,300`) keeps its real delta and random
  tokens don't become false counters — all mutation-tested. The recovered step
  (`sequential.delta`) is now also value-locked, not just its boolean. This plus
  the dedicated `looksSequential`/`looksMonotonic`/`delta` verdict (which Burp
  has no equivalent for) makes counter detection exceed Burp. Closes roadmap #153.
- **Sequencer sample-size + FIPS 140-2 guidance.** The token-analysis result now
  carries a `sampleGuidance` block that makes two thresholds explicit and
  machine-readable: a warning under the recommended ~100-token minimum (with a
  harder "not even estimable" floor below the deep-test threshold), and whether
  the decoded bit-stream reaches the 20,000-bit FIPS 140-2 power-up-test sample.
  Previously the confidence was only an implicit qualitative label with no FIPS
  dimension. Pure helper `Core::sampleSizeGuidance(tokens, decodedBits)`,
  unit- and mutation-tested (the 100-token, deep-test, and 20,000-bit
  boundaries each discriminate). Closes roadmap #186.
- **XML issue report (`GET /api/report/xml`).** Serializes the engagement's
  findings — the same corpus as `report/json` — into a Burp-style XML issue
  report (`<nullockReport>` → `<issue severity/confidence/cvss/fixed>` with
  `name/host/url/cwe/owasp/detail/remediation` elements) for CI systems, SIEM
  ingestion, and XSLT pipelines that consume XML rather than SARIF/JSON. The
  finding→XML pass is a pure, unit-tested helper
  (`ControlLogic::findingsJsonToXml`): every attacker-influenced value
  (host/url/summary) is `xmlAttrEscape`'d, so a summary carrying `</issue>` or
  `<` cannot break the document framing — mutation-tested to prove the escaping
  discriminates.
- **Nuclei-style template scanner.** Author detection templates (JSON) or feed
  real nuclei `.yaml` templates (including `|` literal / `>` folded block
  scalars with chomping, for multi-line request bodies): matchers (status / word
  / regex with and/or + negative, over body / header / all), regex extractors,
  and an active request
  template (method / path / headers / body with `{{BaseURL}}` / `{{payload}}`
  substitution + cluster / pitchfork payload expansion, all bounded). `POST
  /api/template/run` (`{template | yaml | templateId}`) fires the request(s),
  matches each response, and reports a finding per match — so hits feed the
  panel, the CI gate, and the baseline diff. A bundled starter library
  (`templates/detections/`) ships six detections (exposed `.git/config` /
  `.env` / `.DS_Store`, directory listing, missing security headers,
  server-version disclosure); `GET /api/template/list` enumerates them and
  `templateId` runs one by id (path-traversal-guarded).
- **CI security gate.** `GET /api/gate?fail-on=<sev>` returns a pass/fail
  verdict plus a process exit code from the current findings; the one-shot CLI
  `NullockApp --scan <url> --fail-on <sev>` runs the deep audit headless and
  exits `0` / `1` / `2` for direct use in a pipeline. A composite GitHub Action
  (`.github/actions/nullock-scan`) and a reference multi-stage `Dockerfile` wrap
  it.
- **Intruder parity.** Payload-processing rules, payload generators
  (numbers / brute / dates, hard-capped), Grep-Match / Grep-Extract result
  columns, a bounded concurrency + throttle request pool, and save / resume of
  an attack run.
- **Inspector.** `POST /api/inspect` returns a structured view of a raw HTTP
  request/response — parsed query / form / JSON body params, cookies, headers,
  `Set-Cookie` breakdown, and any JWT (decoded header + payload) found in a
  header or cookie.
- **Response-side interception.** The intercepting proxy now holds and lets the
  operator edit/forward/drop *responses*, not just requests.
- **Extension permission model.** JS extensions run in a sandboxed `QJSEngine`
  (no filesystem/network); rewriting traffic is now capability-gated and
  default-deny — an extension must declare `// nullock:permissions
  modify-requests` (or `modify-responses`) or it stays observe-only. Documented
  in `EXTENSIONS.md`.
- **Offline UI.** The web UI vendors React / Babel locally (`ui-v2/vendor/`) and
  drops its CDN dependency, so it runs fully air-gapped.
- **Transparent response decompression** (gzip / deflate) so inspection,
  matching, and reporting see the decoded body.
- **Bearer-token auth** on the control API, mandatory for any off-loopback bind.
- **Asset-dir resolution** via `--ui-dir` / `NULLOCK_UI_DIR` plus auto-detection
  of the install layout.

### Changed
- Passive and active findings carry an explicit `confidence`
  (confirmed / firm / tentative).

### Fixed
- Blind-tunnel (`CONNECT`) passthrough no longer drops the relayed connection.
- Installed and containerized binaries now locate `ui-v2` and the detection
  templates instead of relying on a dev-only relative path.

## [3.7.0] — 2026-07-05
The academy + platform-completion release: the full 50-lab Web Security Academy
clone, the OWASP injection family completed (LDAP / XPath / SSRF /
deserialization / active JWT / CSWSH / host-header / prototype-pollution), OAST
out-of-band auto-confirmation, and the deployable standalone **nullock-oast**
sink + **nullock-workspace** team findings-sync server (both Dockerized).

### Added
- **Web Security Academy clone — 50 labs.** `labs/01`…`labs/50`, each a
  single-file intentionally-vulnerable app mapped to a Nullock probe
  (XXE, CRLF, dangerous HTTP methods, verb tampering, cache poisoning,
  sensitive-file exposure, robots disclosure, predictable session tokens,
  web-cache deception, insecure cookie flags, missing security headers,
  SSRF-to-metadata, OAuth `redirect_uri`, credentials-in-URL, and more).
- **Version → CVE coverage** for Atlassian Confluence (incl. CVE-2023-22515,
  CVE-2023-22518, CVE-2023-22527, CVE-2022-26134) and Jira (CVE-2022-0540,
  CVE-2019-8449, CVE-2019-11581), Jenkins (CVE-2024-23897), Grafana
  (CVE-2021-43798), Apache (CVE-2021-41773/42013), nginx (CVE-2021-23017),
  jQuery, and Bootstrap — all multi-branch ranged so patched builds aren't
  false-flagged, all verified end-to-end.
- **`nullock scope`** — in/out scope management from the CLI
  (`/api/scope/in|out/add|remove`, notes, list).
- **`nullock recon`** now also queries certificate transparency (crt.sh).
- **CSRF PoC generator** — `/api/csrf/poc` + `nullock csrf-poc <row-id>`
  turns a captured request into an auto-submitting HTML PoC.
- **Copy as curl** — `/api/request/curl` + `nullock curl <row-id>`
  reproduces a captured request as a runnable curl command.
- **Multi-mode Intruder** — Sniper / Battering Ram / Pitchfork / Cluster Bomb
  (`/api/intruder/multi`, `nullock intruder multi`), wired through the GUI.
- **Server-side prototype pollution** — `/api/protopollution/test` +
  `nullock protopollution`, the benign json-spaces gadget proven with a
  four-step causal (mutate → observe → revert) check.
- **Host-header injection** — `/api/hostheader/test` + `nullock hostheader`,
  detecting reset/redirect poisoning via sentinel-host reflection into a URL.
- **LDAP injection** — `/api/ldapi/test` + `nullock ldapi`, error-based with
  safe-value corroboration; completes the OWASP injection family.
- **HTTP/3 readiness** — `/api/http3/detect` + `nullock http3`, Alt-Svc h3
  advertisement detection.
- **Version → CVE** for Elasticsearch, Kibana (CVE-2019-7609), and Apache
  Tomcat (Ghostcat, CVE-2020-1938).
- **nullock-oast** — a deployable standalone OAST callback sink (Docker +
  `DEPLOY_OAST.md`) for a public / hosted tier.
- **Release signing** — the release workflow code-signs Windows builds and
  codesigns + notarizes the macOS app when cert secrets are present
  (`RELEASE_SIGNING.md`).
- Permanent regression suites for the CVE database, the finding enricher, the
  request-export transforms, and the Intruder engine — five suites run in CI on
  every push, alongside `scripts/probe_smoke.sh` (active-probe regression
  against in-process mocks).
- **XPath injection** — `/api/xpathi/test` + `nullock xpathi`, error-based with
  safe-value corroboration (mirrors the LDAP probe).
- **SSRF** — `/api/ssrf/test` + `nullock ssrf`, a first-class **fetch-proven**
  probe (cloud metadata incl. decimal/hex IP-encoding denylist bypasses, AWS IMDS
  IAM two-step, `file://` reads, internal-service loopback banners). Confirmation
  requires a response-only signature that's absent from the baseline AND from a
  same-shape non-fetchable shaped-control URL, so reflection/WAF templates can't
  false-positive.
- **Active JWT attacks** — `/api/jwt/test` + `nullock jwt test <url> <token>`,
  the active complement to the offline `jwt` toolkit: it sends forged tokens to a
  live endpoint and confirms acceptance (alg:none + case/empty/absent variants,
  signature-not-verified, weak-HMAC-secret, and RS256->HS256 algorithm confusion
  when a public key is supplied). Sound via a no-token/valid/forgery
  calibration with a second-send re-confirm. (Burp does JWT testing only via a
  paid extension.)
- **Cross-site WebSocket hijacking (CSWSH)** — `/api/cswsh/test` + `nullock
  cswsh`, an active probe that sends a cross-origin WebSocket upgrade and
  confirms only on `101` + a valid `Sec-WebSocket-Accept` (RFC 6455), with a
  no-Origin control to tell an origin-validating endpoint from a non-WS one.
- **Insecure deserialization** — `/api/deser/test` + `nullock deser`, an active
  probe for Java/PHP/Python/Ruby/.NET. Uses a well-formed-vs-malformed
  differential (a real deserializer accepts a benign well-formed object and errors
  on a malformed one; a shape-keyed WAF errors on both) so it's sound where a
  naive error gate is not. Payloads are inert canaries that fail before any gadget.
- **Out-of-band confirmation via OAST.** `nullock oast blast` now sprays blind
  **SSRF**, **OS command injection (RCE)**, **XXE**, and **Log4Shell** payloads at
  a target; a callback to the in-process HTTP sink (or the DNS sink, for the
  jndi/DNS Log4Shell leg) auto-confirms the class via the correlator — a
  true-positive-by-construction confirmation no response echo can give.
- **Time-based blind SQLi** is now exercised in the deep-audit battery (opt-in,
  `nullock sqli <url> blind`) with differential-timing confirmation.
- **Content/directory discovery** — `/api/content/discover` + `nullock content`,
  a soft-404-calibrated wordlist sweep.
- **Subresource Integrity** passive check — flags cross-origin `<script>` without
  `integrity=` (supply-chain risk, CWE-353).
- **nullock-workspace** — a deployable standalone team-findings sync server
  (SQLite, bearer-key auth, identity-key merge) with `nullock workspace push|pull`
  CLI, completing team-workspaces Phase 1 (Docker + `DEPLOY_WORKSPACE.md`).
- Design docs for team workspaces and enterprise SSO (`design/`).

### Changed / Fixed
- **Release workflow startup failure fixed.** The optional signing steps had
  referenced the `secrets` context in a step `if:` (not permitted), which made
  GitHub reject the workflow at parse time on every push; they now no-op
  in-script when the secret is absent.
- **CVE database accuracy audit.** Web-verified every entry against
  NVD/vendor advisories; corrected ~11 entries (per-branch ranges that
  false-positived patched builds, wrong CVSS scores, mislabeled vulns) and
  removed 3 bogus/false-positive entries.
- **Finding enricher coverage.** ~53 of 97 emitted finding kinds were
  shipping with empty CWE/OWASP; added family-prefix fallbacks + a generic
  last-resort so every finding is enriched.
- **CI restored to green.** The Windows build had been failing at the Qt
  install step (`qtquickcontrols2` is not a Qt 6 aqt module); fixed, wired
  the regression suites into the pipeline, and re-synced the marketplace
  docs mirror.

## [3.6.0] — 2026-06-17
The platform release: a network scanning + reporting + recon suite.
Port-scan → findings bridge, recon → vuln pipeline (`nullock pipeline`),
WAF/CDN and robots/sitemap recon, a live CVE-feed overlay (`nullock cvefeed`),
and engagement reporting — HTML (A–F grade), JSON bundle, CycloneDX SBOM,
OWASP/compliance coverage, asset inventory, posture grade, baseline diff.
Each feature shipped with an adversarial review and a regression test.

## [3.5.0] — 2026-06-11
The active-testing climb: a full battery of injection, access-control, and
misconfiguration scanners (SQLi error + blind, NoSQLi, XXE, SSTI, OS cmd-i,
reflected XSS, CRLF, LFI/path-traversal, IDOR/BOLA, mass assignment, active
CORS, verb tampering, open redirect, web cache poisoning + deception,
header/CSP audit, secret scanning, request smuggling), plus identification
modules (service→CVE, TLS inspection, fingerprint, HTTP methods, subdomain
takeover, sensitive-file exposure) and **ScopeGuard** — one authorization
gate on every active test. HTTP-client correctness fixes throughout.

## [3.4.0] — 2026-06-11
Active testing & API-security: OAST auto-correlation + active OOB blast +
DNS sink, hidden-parameter mining, IDOR/BOLA, mass assignment, active CORS
exploitability. Each with adversarial review and false-positive guards.

## [3.3.0] — 2026-06-09
The "above the paid tools" release: CVE correlation, GraphQL attack probes,
DOM-XSS taint analysis, Repeater chains, and a JWT attack toolkit. Every
finding gained CWE / OWASP Top-10 2021 / CVSS v3.1 / one-line fix tags.

## [3.2.0] — 2026-06-02
Repeater side-by-side response diff with byte-level highlighting; streaming
scoped history export; SQLite write batching (~40% less capture overhead at
200k rows).

## [3.1.4] — 2026-05-18
Linux CA install fix under Wayland; match-and-replace empty-body fix;
`nullock vacuum` to compact history.

## [3.1.0] — 2026-04-29
JavaScript extension API (onRequest/onResponse hooks); glob scope syntax;
large-response streaming leak fix.

## [3.0.0] — 2026-03-11
First native desktop release: cross-platform Qt6/C++20 app over the same
control server the CLI drives, SQLite-backed history (200k+ rows), config
under `~/.nullock/`.

[Unreleased]: https://github.com/Bikebrainz/Nullock/compare/v3.7.0...Nullock
[3.7.0]: https://github.com/Bikebrainz/Nullock/compare/v3.6.0...v3.7.0
