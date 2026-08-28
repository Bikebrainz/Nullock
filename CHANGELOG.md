# Changelog

All notable changes to Nullock are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/). Dates are when a build went out.

The public, prose version lives at
<https://bikebrainz.github.io/Nullock/changelog.html>; this file is the
developer-facing record.

## [Unreleased]

### Fixed
- **"Send to Repeater" could load the wrong request after history eviction.**
  `/api/repeater/tab/addFromHistory` treated its argument as a live window index,
  and the UI passes `row.id - 1` — which equals the index only until the bounded
  in-memory history window starts evicting older rows (then `firstId > 1`). Past
  that point it silently loaded a DIFFERENT row's request (or none). Added
  window-eviction-safe `ProxyModel::hostById/portById/tlsById` and
  `Repeater::addTabFromHistoryById(id)` (mirroring the existing `requestRawById`
  id→index mapping), plus a `POST /api/repeater/tab/addFromHistoryId` endpoint
  that resolves the source row by its stable id. Verified live (valid id → tab
  created, bogus id → rejected). ui-v2's "send to Repeater" now calls
  `repeaterTabAddFromHistoryId(row.id)` instead of the index-based action, so
  the fix is reachable from the GUI.
- **Global search negate mode double-counted / mis-matched `where=both`.** A
  negative search ("find items that do NOT contain X") is a whole-item concept,
  but the match ran per text: with `where=both`, a proxy row or Repeater tab was
  checked for the request AND the response independently, so a row that carried
  the pattern in its request but not its response was still reported as a
  "does-not-contain" hit, and a row absent from both was reported twice. Negate
  now evaluates every in-scope text of an item together and emits one hit only
  when the pattern is absent from all of them (`where: "item"`). Verified live
  (no duplicate ids).
- **`/api/findings/grouped` ignored operator triage.** The grouped findings
  rollup read the raw scanner findings and applied none of the triage marks the
  snapshot path honours — so a finding the operator had suppressed, marked
  false-positive, or soft-deleted still appeared in the grouped view, at its
  un-overridden severity. It now runs the same `FindingTriageLogic` predicates:
  suppressed-kind / false-positive / deleted findings drop out, and a severity
  override replaces the scanner's severity. Verified live (suppressing a kind
  removes its group).
- **Decoder/Workbench decoding lost binary bytes to U+FFFD.** The
  `base64`/`hex`/`octal`/`binary` decoders returned `QString::fromUtf8` over the
  raw decoded bytes, so any non-UTF-8 octet (the common case when decoding a
  binary blob) was silently replaced with the U+FFFD replacement character
  before the response was even built. The decoders now preserve the exact octets
  (`Transcode::Result::outputBytes`), and `POST /api/transcode` emits them as an
  additive base64 field (`outputBase64`) so a Hex view / binary round-trip is
  lossless. Mutation-proven. (Removes the backend blocker on the Decoder
  Text/Hex view item.)
- **Session-handling rules reserialized requests they didn't touch.** A rule
  that matched and produced a value flipped an internal `modified` flag *before*
  the inject switch, so an `InjectIntoBody` rule whose `{{placeholder}}` was
  absent from a non-form body (a no-op) still forced `applyToRequestBytes` to
  reparse and reserialize the whole request — reordering headers and recomputing
  Content-Length on a hand-crafted request no rule really changed. The body
  transform is now the pure, mutation-proven `injectIntoNonFormBody`, and
  `modified` is set only when an injection actually changes the request.
- **Intruder save/resume dropped request-shaping config.** `saveRun()`/`loadRun()`
  round-tripped through `RunConfig`, which omitted `globalEncodeChars`
  ("URL-encode these characters"), the recursive-grep settings
  (`recursiveGrep`/`Seed`/`Count`) and the redirect policy
  (`followPolicy`/`followCookies`) — so a reloaded attack silently reset those to
  defaults and fired **materially different requests** than the one that was
  saved (no URL-encode safety net, redirect-follow off, recursive-grep off). All
  six fields now round-trip; mutation-proven in `intruder_persist_logic_test`.
- **Extension utils `htmlDecode` truncated supplementary-plane entities.** A
  numeric HTML entity naming a code point above U+FFFF (e.g. `&#128512;` 😀) was
  assigned into a 16-bit `QChar`, silently truncating U+1F600 to a wrong BMP
  character (U+F600). It now decodes via UCS-4 (emitting the correct surrogate
  pair), and a surrogate-range entity (`&#xD800;`) is rejected as a non-scalar
  value and kept literal. (Surfaced by an adversarial audit sweep.)

### Security
- **Seven more injection-detector checks locked by mutation-proven tests
  (no behaviour change).** A second adversarial coverage audit over the classic
  injection probes found seven low-level checks whose silent breakage no test
  would catch — each verified by mutating the source and confirming only the
  targeted case fails: (1) `xss_logic` — the standard HTML comment terminator
  `-->` close was never exercised (the one comment positive closed via the rare
  bogus `--!>` form), so breaking it would silently suppress every reflection
  after a normal HTML comment. (2) `sql_logic` — the MySQL error signature's
  `MySqlException` / `com.mysql.jdbc` / `MySQLSyntaxErrorException` driver/class
  alternatives (all the .NET/Java stack-trace forms) were untested; only the
  `SQL syntax…MySQL` prose branch was. (3) `cmd_injection_logic` — the
  buildRequest CR/LF guard on carried header **names** was untested (only the
  value guard was), so its removal would splice an attacker header into every
  probe shot. (4,5) `xxe_logic` + `ldap_logic` — the carried-Accept-Encoding
  drop's case-**insensitivity** was unpinned, so a lowercase `accept-encoding`
  (HTTP/2 / HAR imports) would survive, the server would gzip, and the file-read
  / error fingerprint would be scanned over compressed bytes → a real hit reads
  clean. (6) `xpath_logic` — the Java signature's bare `XPathExpressionException`
  class-name alternative was never exercised in isolation (the Java case matched
  via the `javax.xml.xpath` prefix). (7) `nosql_logic` — `trueGroupAgrees`'s
  status-equality conjunct (`neStatus == gtStatus`) was unpinned, so an operator-
  keyed status flip could fabricate a NoSQL-injection finding. Gauntlet green
  (ctest 100/100, probe_smoke 158/158). Test-only.
- **Six security-critical detector checks locked by mutation-proven tests
  (no behaviour change).** An adversarial coverage audit found six specific
  branches/regexes/thresholds whose silent breakage no existing test would
  catch — each a real regression that would stop detecting an attack/leak or
  fabricate a finding. Discriminating cases were added and each was verified by
  mutating the source and confirming only the targeted case fails: (1)
  `secret_logic` **private-key-block** — the scanner's *only* `critical`
  pattern was tested for the RSA header alone; the OPENSSH and unprefixed
  PKCS#8 header forms are now pinned (dropping the OPENSSH alternative, or
  forcing the algorithm prefix, is caught). (2) `jwt_probe_logic` **buildRequest
  CR/LF guards** on carried header names *and* values — untested, so a silent
  removal would turn the JWT probe itself into a header-injection / request-
  smuggling vector; both now pinned. (3) `jwt_tool` **hashForAlg HS384/HS512
  digest selection** — a regressed branch silently HMAC-SHA256s an HS384/512
  token so secret recovery quietly fails; pinned with tokens signed
  independently of `hashForAlg`. (4) `cve_database` **inclusive-upper-bound
  `<=`** — the `versionEndIncluding` boundary (a host on the exact last-affected
  version) had zero coverage; pinned. (5) `method_audit_logic` **traceEchoed's
  User-Agent conjunct** — the second half of the XST proof was unpinned, so a
  405 page that merely echoes the request line could be mis-reported as
  cross-site-tracing; pinned. (6) `transcode` **looksLikeBase64 printable-ratio
  threshold** — the hex-vs-base64 disambiguator was never exercised; pinned.
  Gauntlet green (ctest 100/100, probe_smoke 158/158). Test-only.
- **Proxy credentials no longer leaked to the origin.** When the proxy
  re-serialized a request for the upstream origin
  (`serializeRequestForOrigin`), it stripped only `Proxy-Connection` and
  forwarded `Proxy-Authorization` verbatim — leaking the client's credentials
  for *the proxy* to every target it connected to. Both proxy-hop headers are now
  stripped via a pure, mutation-proven `HttpLogic::isProxyHopRequestHeader`
  predicate (ordinary `Authorization` is still forwarded). This also covers the
  Repeater/Intruder send paths, which reuse the same serializer.
- **method-audit finding emission locked by tests.** The mapping from an
  advertised Allow list + the three Cross-Site-Tracing echo probes to the exact
  findings emitted (`dangerous-http-methods`, `webdav-enabled`,
  `http-trace-enabled`, `http-track-enabled`) was inline on `audit()`'s network
  path and therefore untested &mdash; a kind rename or a broken condition would
  silently stop flagging TRACE/TRACK/WebDAV/dangerous methods. Extracted it into
  the pure `MethodAudit::classifyMethods()` and locked every input→kind→severity
  case with mutation-proven unit tests (defeating the write-method branch or
  mislabelling the TRACK kind now fails only its targeted assertions). No
  behaviour change.

### Added
- **Active OGNL / Apache-Struts2 injection detection.** The SSTI active
  tester's two-expression arithmetic proof gained the `%{ }` delimiter family
  — the syntax Apache Struts2 evaluates as OGNL and the classic S2-045 /
  CVE-2017-5638 injection vector. Previously OGNL was only inferred from
  version-based CVE correlation; now an OGNL-parsed sink is *actively confirmed*
  the same unambiguous way every other engine is: `pre%{a*b}sep%{c*d}suf` is
  injected and `confirmsArithmetic()` requires both products with the literal
  separator preserved and neither raw expression echoed, so a real Struts2 sink
  confirms while pure reflection or a single-expression calculator do not. No
  other family uses `%{ }`, so a hit uniquely fingerprints OGNL/Struts2. Added
  one row to `ssti_tester.cpp` `families()` (reusing the proven engine, not a
  parallel probe). Live-proven in `scripts/probe_smoke.sh` by a new `ssti-ognl`
  mock that evaluates only `%{N*N}` (not Jinja `{{ }}`): `/api/ssti/test`
  confirms it with `engines` containing `OGNL` and not `Jinja2`, and deleting
  the family drops the case to `confirmed:false` while the other SSTI cases
  stay correct (mutation-proven). Gauntlet: ctest 100/100, probe_smoke 158/158.
- **Named configuration-preset library (Burp's "configuration library").**
  A global shelf of named config presets you save the current setup into and
  switch between later, persisted to `AppData/config-presets.json` as a
  `{name: document}` map so a preset survives across projects. Four endpoints:
  `POST /api/config/presets/save` (snapshots the live config), `GET
  /api/config/presets` (lists names), `POST /api/config/presets/load` (applies
  a preset to the live editors) and `POST /api/config/presets/delete`. It is
  built directly on the existing config export/import: `save` captures live
  state with the SAME code `/api/config/export` uses and `load` applies with
  the SAME per-section code `/api/config/import` uses (both extracted into
  shared `captureConfigSections()`/`applyConfigSections()` lambdas), so a
  preset is byte-for-byte an export document. Preset names are validated
  (`ControlLogic::presetNameValid`: 1-64 chars of letters/digits/space and
  `- _ .` only — path separators, control chars and dot-only names rejected)
  and listed sorted (`ControlLogic::presetNames`); both are pure and
  mutation-proven in `Tests/control_logic/control_logic_test.cpp`. Verified
  live end-to-end (14/14): add a scope marker, save a preset, remove the
  marker, load the preset back and confirm the marker returns (the apply path),
  then list/delete; invalid names and a missing-preset load are rejected. The
  ui-v2 preset switcher is not built yet, so the roadmap item stays partial.
- **Lab 54: XPath injection (error-based confirm + boolean login
  bypass).** A new teaching lab (`labs/54-xpath-injection/`) alongside the
  existing 53. A staff login endpoint builds an XPath filter against an
  in-memory XML user store by plain string concatenation -- the same bug
  class as SQLi, against `lxml`/libxml2 instead of a SQL engine. A lone
  quote in the `username` field breaks the expression's syntax outright
  and a real `lxml.etree.XPathEvalError: Invalid predicate` leaks back --
  exactly the error-based fingerprint `Src/Core/Networking/xpath_logic.cpp`'s
  engine-signature matcher and the `xpathi` active probe
  (`Src/Core/Networking/xpath_injection.cpp`) already send and detect
  (`username` sits in the probe's default param list, so no manual param
  hint is even needed). Separately, a well-formed boolean payload
  (`password=' or 1=1 or 'a'='a`) exploits XPath's `and`-binds-tighter-
  than-`or` precedence to make the predicate true regardless of the real
  password -- the match count jumps from the at-most-one a legitimate
  login produces to all three directory entries, and the app trusts the
  *typed* username for identity, logging the attacker in as admin with no
  correct password. Verified end-to-end against a real Flask+lxml run:
  baseline and a benign value never error, the quote breaker reproduces
  the exact `XPathEvalError`, the boolean payload logs in as admin with
  `matchCount:3`, and `/flag` only solves via that genuine multi-match
  bypass (a wrong password without injection stays 403).
  `scripts/labs_site.py` regenerated (`docs/labs/`, `ui-v2/labs-data.js`,
  new `xpath-injection` Injection-category keyword); README.md and
  docs/index.html's 53->54 lab-count strings updated alongside.
- **Lab 53: JWT `kid` header injection (path traversal -> empty-key
  forgery).** A new teaching lab (`labs/53-jwt-kid-injection/`) alongside
  the existing 52. The token's own `kid` header names which on-disk key
  file the server HMAC-verifies against; the lookup joins `kid` onto a
  fixed `keys/` directory with no traversal check, so `kid="/dev/null"`
  (an absolute path drops the base directory outright -- a real
  `os.path.join` gotcha) or twenty doubled `....//` segments (surviving a
  naive single-pass `kid.replace("../", "")` filter that a plain repeated
  `../` gets caught by) point the check at a guaranteed-empty file --
  sign the forged token with an empty key and it verifies. This is the
  exact primitive `Src/Core/Networking/jwt_probe_logic.cpp`'s
  `kidInjectionVariants()` already probes for (plain `/dev/null`, the
  Windows `NUL` device, and both plain and doubled-dot traversals,
  differentially against a blank-secret baseline so it isn't
  double-counted as a plain empty-secret finding). Verified end-to-end:
  the real per-run key logs in normally, the blocked repeated-`../` kid
  gets 401, the absolute-path and doubled-dot kids both forge an
  admin token, and `/flag` only solves off one of those two working
  forgeries. `scripts/labs_site.py` regenerated (`docs/labs/`,
  `ui-v2/labs-data.js`); README.md and docs/index.html's 52->53 lab-count
  strings updated alongside.
- **Lab 52: LDAP injection (filter metacharacter injection + wildcard
  bypass).** A new teaching lab (`labs/52-ldap-injection/`) alongside the
  existing 51. A staff-directory search builds an LDAP-style filter by
  string concatenation; a filter-breaking value (`*)(`, `)(`, etc.) leaks a
  python-ldap-shaped `ldap.FILTER_ERROR` -- exactly the error-based
  detection the existing `ldapi` active probe (`Src/Core/Networking/
  ldap_injection.cpp`) already sends and fingerprints, so `nullock ldapi`
  confirms the bug automatically. Separately, a well-formed wildcard
  (`cn=admi*`) resolves to the `admin` entry without ever matching the
  app's literal-string `"admin"` blocklist, demonstrating the semantic
  (non-error) half of LDAP injection alongside the syntax-breaking half.
  Verified end-to-end: baseline and a benign value never error, all five
  of the probe's filter-breaker payloads reproduce the 500 consistently,
  and `/flag` solves only via the wildcard bypass, not the blocked literal
  query. `scripts/labs_site.py` regenerated (`docs/labs/`,
  `ui-v2/labs-data.js`); README.md and docs/index.html's 51->52 lab-count
  strings updated alongside.
- **Lab 51: JWT algorithm confusion (RS256 -> HS256).** A new teaching lab
  (`labs/51-jwt-alg-confusion/`) alongside the existing 50, past the v4
  roadmap's original 50-lab goal. The app signs with RS256 and publishes its
  RSA public key at `/pubkey`; the verifier dispatches on the token's own
  `alg` header and, for `HS256`, HMAC-verifies against that public key's PEM
  bytes -- so anyone who fetched `/pubkey` can forge an admin token, the
  exact primitive `/api/jwt/forge`'s `attack: "hs256"` documents ("pass the
  server's PEM public key as secret"). Solved only by a token forged that
  way, not a legitimately-issued one (`/login` never issues `role: admin`).
  `scripts/labs_site.py` regenerated (`docs/labs/`, `ui-v2/labs-data.js`),
  and its own hardcoded lab-count strings (footer, hero, meta description)
  are now derived from the live lab list instead of a fixed "50"/"Fifty" so
  they can't drift again the next time a lab is added.
- **Sequencer live capture: literal start/end-delimiter token extraction.** The
  capture extractor gains a `FromDelimiter` mode alongside header/cookie/json/
  regex/status: `parseExtractFrom` accepts `"delimiter"`/`"delim"`, and
  `extractToken` returns the substring between the first `<start>` and the next
  `<end>` (empty start = from the beginning, empty end = to the end; key encoded
  as `<start>\x1f<end>`). Pure, mutation-proven. (Roadmap: live-capture custom
  location; still partial pending the ui-v2 delimiter fields.)
- **Session rules: custom URL include/exclude scope.** A `SessionRule` now carries
  `includeUrls`/`excludeUrls` glob lists (JSON round-tripped via
  `/api/session-rules`), and rule matching consults the pure, mutation-proven
  `SessionRulesLogic::urlScopeMatches` (globs matched against `host`+path with the
  query stripped; empty include = all URLs; a matching exclude rejects, so exclude
  beats include). This makes "everything except /logout" expressible &mdash;
  `include=[*]`, `exclude=[*/logout*]` &mdash; which a single host+path glob could
  not. (Roadmap: session-rule URL scope; still partial pending "use suite scope"
  and protocol/port matching.)
- **CA certificate DER export.** `GET /ca.der` (and Burp's `/cert` alias) now
  serves the MITM root CA as `application/pkix-cert` for clients that import DER
  only, converting the existing PEM via the pure, OpenSSL-free
  `ControlLogic::pemCertToDer`. Verified live: the served DER parses in openssl
  and its fingerprint matches `/ca.pem`. (Roadmap: proxy CA export/import; still
  partial pending PKCS#12 export/import and CA regenerate.)
- **Inspector: server-side value decode chains.** `inspectRequest` now runs the
  bounded recursive `Transcode::smartDecode` over each query/cookie/body-param
  value and, when it makes progress, attaches `decoded` + `decodeChain` (the
  ordered ops) to that param &mdash; covering url/base64/html **and** hex/jwt. So
  a CLI/report/API consumer of `/api/inspect` sees what an encoded token really
  is, not only the ui-v2 client detector (which covers url/base64/html). A plain
  value gets no chain. Mutation-proven.
- **Inspector: HTTP/2 pseudo-header projection.** `inspectRequest` now emits a
  `pseudoHeaders` array (`:method`, `:path`, `:authority` from the Host header,
  `:scheme` defaulting to `https`) so the Inspector can show the h2 view of any
  request. (Roadmap: Inspector h2 pseudo-headers &mdash; display half; editing,
  the h1↔h2 toggle, and on-wire emission remain.)
- **MITM leaf certs for IPv6 targets (IP SANs).** A strict, Qt6::Core-only
  `CertLogic::isIpv6Literal` (full / `::`-compressed / embedded-IPv4 forms;
  rejects zone ids, a second `::`, and malformed groups) is now consulted by
  `sanEntryForHost` (emitting an `IP:<addr>` SAN) and `isValidHostForCert` (which
  previously rejected the `:` in an IPv6 literal, so `https://[v6]/` targets never
  minted a leaf and fell through to a blind tunnel). Mutation-proven. (Roadmap:
  proxy &mdash; per-host IP/IPv6 leaf certs; still partial pending multi/wildcard
  SANs and the socket-level MITM handshake.)
- **Content discovery: filename-mutation rules.** `POST /api/content/discover`
  gains a `mutations` flag: when set, each (extension-expanded) candidate is also
  probed as its common backup/temp/editor artifacts &mdash; `word~`,
  `word.bak`/`.old`/`.orig`/`.save`/`.tmp`/`.1`, and a directory-aware vim swap
  `.<leaf>.swp` &mdash; the "someone left a backup of the live file" sweep. Pure,
  mutation-proven `ContentDiscovery::mutateFilenames`, bounded by the same
  `maxRequests` cap as the extension expansion. (Roadmap: target &mdash; content
  discovery extension bruteforce + mutation rules; still partial pending the
  ui-v2 mutations checkbox.)
- **Comparer: exact byte-level diff (Bytes mode).** The Comparer gains a
  binary-safe `bytes` mode: `Compare::diffBytes()` diffs two raw byte buffers
  (one hex token per octet through the existing LCS core), and `POST /api/compare`
  accepts base64 inputs (`aBase64`/`bBase64`) that are decoded to raw octets
  before diffing. So binary session tokens, serialized objects and images now
  diff exactly instead of being folded through UTF-16 &mdash; e.g. the invalid-UTF-8
  octets `0x80` and `0x81` are reported as different rather than both collapsing
  to the replacement character. Mutation-proven. (Roadmap: Comparer byte-level
  comparison &mdash; now at parity.)
- **Inspector: full body-parameter parsing (JSON / multipart / XML).** The
  request Inspector now populates its params view for every common body type:
  - **JSON** is flattened recursively into Burp-style dotted/bracketed leaves
    &mdash; `user.name`, `user.addr.city`, `tags[0]`, `items[1].id` &mdash; instead
    of collapsing a nested object/array to a bare `{…}`/`[…]` placeholder; it also
    handles a top-level JSON array (`[0].x`) and shows a `{}`/`[]` placeholder for
    empty containers so a key never vanishes.
  - **multipart/form-data** parses each part from the RAW bytes (so a binary part
    is never transcode-mangled): a text field shows `name=value`, a file field
    shows `[file: <filename>, <N> bytes]`.
  - **XML** flattens to element-path leaves (`order.item.sku`) plus attributes
    (`order@id`).
  All parsers are depth-/count-bounded (maxDepth 64, maxParams 2000). Mutation-
  proven (four mutants). (Roadmap: Inspector body params &mdash; now at parity.)
- **Intruder payload type: Custom iterator.** A new `iterator` payload generator
  produces a positional cartesian product &mdash; give it N positions, each its
  own list of items, plus a separator, and it emits every combination
  `pos[0][i] + sep + pos[1][j] + …` in odometer order (last position varies
  fastest). Reachable via `type: "iterator"` on `POST /api/intruder/generate`
  (preview) and `/api/intruder/set`. Like the other generators it is a pure,
  hard-capped `IntruderGenerators::customIterator`: a product past the 100k cap
  truncates in count while every emitted payload stays a complete combination,
  so it never OOMs. Mutation-proven. (Roadmap: intruder &mdash; Payload type:
  Custom iterator, now at parity.)
- **Issue definitions library.** `GET /api/issue-definitions` serves a browsable
  catalog of every issue KIND the scanner can report (198 at time of writing),
  independent of whether any has been found &mdash; each with its CWE, OWASP Top 10
  category, CVSS base score and vector, compliance tags, default confidence, and
  canonical remediation. It is generated from the SAME hand-curated enrichment
  table applied to live findings (via a new `FindingEnricher::issueCatalog()`),
  so the library can never drift from what a real finding is stamped with. This
  is the "what can this tool find" reference for scoping a test or writing
  methodology. (Roadmap: target &mdash; Issue definitions; still partial pending
  an in-app browse UI and Burp-style long-form per-issue background prose.)
- **Reporting: report customisation across all four report sinks.** Every report
  output now honours an issue-selection filter &mdash; `minSeverity`,
  `minConfidence`, `includeKinds`, `excludeKinds`, `includeFixed` &mdash; through
  one shared, mutation-proven predicate (`ControlLogic::findingPasses`):
  `GET /api/report/json` and `GET /api/report/xml` read it from the query string;
  `POST /api/report/build` (Markdown) and `POST /api/report/html` read it from the
  JSON body. So a report can drop informational noise or narrow to, say,
  high-and-above confirmed SQLi. The two human reports also accept a custom
  `title` and an `appendix`, and print a "showing X of Y (filtered)" note.
  `report/json` reports `findingsTotal` (included) vs `findingsTotalAll` and a
  `filtered` flag and keeps posture/coverage over the FULL set (engagement truth),
  while the standalone HTML/Markdown reports reflect the included set throughout
  (Burp's report-wizard behaviour). Confidence ranking spans the enriched
  `confirmed`/`firm`/`tentative` taxonomy and the raw `high`/`medium`/`low` one.
  (Roadmap: platform &mdash; report customisation; still partial pending a
  detail-level toggle and full request/response evidence embedding.)
- **Sequencer: analysis summary with a confidence level and amount of data
  analyzed.** Token analysis now emits a `summary` object headlining the result
  the way Burp's Sequencer does: the verdict and score, a **confidence**
  (`low`/`medium`/`high`) driven by sample adequacy &mdash; too few tokens or
  below the deep-test floor is `low`, an adequate token count under the
  20,000-bit FIPS 140-2 sample is `medium`, and adequate tokens with a
  FIPS-sized decoded bitstream is `high` &mdash; plus the significance level, the
  effective-bits-per-token estimate, and an explicit accounting of how much data
  backed it (`tokensAnalyzed`, `avgTokenLength`, `decodedBits`,
  `meetsRecommendedSample`, `meetsFipsSample`, and a prose `dataAnalyzed` line
  tying the sample size to the estimate). Confidence is tied to the data, not to
  the verdict, so a "looks-random" call on 20 tokens is honestly flagged as
  low-confidence. Mutation-proven. (Roadmap: sequencer &mdash; analysis summary;
  still partial pending a per-significance-level entropy curve and per-flag
  score attribution.)
- **Sequencer: significance-level (alpha) selector.** Token analysis now takes a
  significance level &mdash; `analyzeTokens(tokens, alpha)` /
  `Sequencer::analyze(tokens, sig)` and an optional `significanceLevel` on
  `POST /api/sequencer/analyze` &mdash; and grades EVERY bit-level test at that
  level (the Bonferroni-corrected per-position / pairwise tests at
  `alpha/N`), re-judging the whole suite looser or stricter in one shot. Each
  test now also emits its **p-value**: the two-bit (&chi;&sup2;, 3 dof), poker
  (15 dof), runs (z), run-length (5 dof) and lag-1 serial-correlation tests
  gained one alongside the p-value monobit already reported, so no result needs
  hand-judging against a memorised critical value. `alpha` defaults to 0.01
  (FIPS/NIST) and is clamped to `[1e-6, 0.2]`; at 0.01 the grading reproduces
  the previous hard-coded critical values exactly, so the verdict on existing
  corpora is unchanged. Mutation-proven (defeating the alpha threading fails
  only the targeted assertions) and verified live end-to-end. (Roadmap:
  sequencer &mdash; significance-level selector; still partial pending a UI
  control and alpha-grading of the keyspace estimate.)
- **Configuration import/export as JSON.** `GET /api/config/export` emits a
  portable, versioned document &mdash; `{format:"nullock-config", version,
  sections}` &mdash; carrying scope (in/out/notes/advanced), match&amp;replace
  rules, session-handling rules and intercept rules, so a tuned setup can be
  handed to a teammate or checked into a repo. `POST /api/config/import`
  validates the envelope (refusing a non-Nullock document and one from a
  newer major version) and applies each section it carries through the EXACT
  setters behind the live `/api/scope`, `/api/rules`, `/api/session-rules` and
  `/api/intercept/rules` editors &mdash; import and the editors are one code
  path. The envelope logic is pure and mutation-proven (version-gate and
  format-gate mutants each fail only their targeted case). Still partial vs
  Burp until a named-preset *configuration library* (a shelf of switchable
  named configs) is built. (Roadmap: platform &mdash; configuration
  import/export.)
- **OAST correlation persists across restarts.** The Collaborator-style OAST
  correlator now saves its token registry (token &rarr; originating row/param/probe)
  and its already-confirmed set to a file under the app data dir (atomic write on
  every registration and confirmation) and reloads it on startup. So an overnight
  out-of-band callback that arrives *after* a restart still correlates to the
  token minted before it &mdash; emitting its confirmed finding instead of being
  lost &mdash; and an interaction already reported is never re-reported. The
  serializer is versioned and Core-only unit-tested (a corrupt/old file loads
  empty rather than half-loading). (Roadmap: platform &mdash; Collaborator
  interaction persistence; the raw poll-log ring + DNS-hit retention remain
  in-memory, tracked as the remaining partial.)
- **Sequencer: per-position effective entropy.** Alongside the global
  bits/char&times;length keyspace estimate, token analysis now reports
  `shannon.perPositionEffectiveBits` &mdash; the sum of log2(observed alphabet
  size) across each column of the modal-width cohort. This credits a token's TRUE
  region-by-region keyspace: a token that is hex in columns 0&ndash;7 (4 bits
  each) but drawn from a reduced alphabet in later columns scores its real bits,
  not the blended global average the length-based figure assigns to both regions.
  It is a conservative lower bound that tightens with more samples. (Roadmap:
  sequencer &mdash; "Effective entropy … summed across positions".)
- **Sequencer: per-bit-position monobit test.** The FIPS/NIST monobit frequency
  test now runs at every bit position independently (across the modal decoded-
  width cohort), not just once over the whole concatenated stream. A single
  stuck or biased bit &mdash; diluted 1:(width&times;8) in the aggregate test &mdash; is
  now caught: reported as `bitLevel.perBitMonobit` and folded into the failure
  verdict. A Bonferroni-corrected threshold (0.01/positions) keeps the family-
  wise false-positive rate at ~1% so a clean corpus is never flagged. (Roadmap:
  sequencer &mdash; "FIPS monobit … at every bit position independently".)
- **Sequencer: per-position character chi-square + a chi-square p-value.** Token
  analysis now runs a real chi-square of each column's character distribution
  against uniform-over-its-alphabet, with a p-value per column (via a new
  exported `chiSquareSurvival()` &mdash; the regularized upper incomplete gamma,
  unit-tested against standard critical values) and a Bonferroni-corrected
  pass/fail. Unlike the entropy-vs-strongest-sibling reference, this flags a
  generator biased *uniformly* across every column. Reported as
  `positional.charChiSquare`. (Roadmap: sequencer &mdash; "per-position chi-square
  … with a p-value per position".)
- **Sequencer: inter-bit-position correlation test.** Beyond the byte lag-1
  serial correlation, analysis now correlates every *pair* of bit positions
  across tokens (2&times;2 contingency &rarr; chi-square &rarr; p-value), flagging pairs
  that move together &mdash; one bit derivable from another, i.e. real keyspace
  smaller than the bit count implies (a truncated-LCG bit-3-vs-bit-47 relationship
  invisible to any single-position test). A Bonferroni correction over all pairs
  is the "significance adjusted for interdependence". Reported as
  `bitLevel.bitCorrelation`. (Roadmap: sequencer &mdash; "correlation between
  distinct bit positions …".)
- **Repeater: record a request chain straight from Proxy history.** The
  SCANS tab's Request chain section gains a "Record from history" control:
  type one or more Proxy history row IDs and it builds the chain-step JSON
  from those captured requests (via the existing `/api/chain/record`
  backend, previously reachable only through the raw HTTP API), dropping it
  straight into the editable steps textarea instead of requiring the steps
  to be hand-written from scratch.
- **Intruder: "Skip if matches regex" payload-processing rule.** A `skip-if-matches`
  rule (arg = regex) drops any payload whose transformed-so-far value matches,
  before the request is fired &mdash; matching Burp's rule. Skipped payloads are
  filtered out before the result table is built, so counts reflect only what was
  actually sent. An empty or invalid pattern never skips. (Roadmap: intruder.)

### Fixed
- **CSWSH probe: a transient failure on the first Origin aborted the whole sweep.**
  The WebSocket cross-origin sweep tries a sentinel, `null`, and host-derived
  subdomain/scheme variants, and the FIRST valid upgrade confirms a hijack. But a
  dead-host early-bail keyed only off the FIRST origin's handshake &mdash; so a
  transient failure there (TLS flake, a server that RSTs an unexpected Origin)
  returned before the subdomain/scheme variants were tried, missing a real CSWSH
  on a later variant (a false negative). It now bails only when EVERY variant
  comes back dead, via the pure, unit-tested `wsHandshakeDead`.
- **Subdomain-takeover test: a healthy 200 quoting a vendor phrase was reported
  as a MEDIUM takeover.** The status-aware matcher demotes a branded fingerprint
  seen on a live 2xx/3xx page to "possible" confidence (a dangling service serves
  its unclaimed page as a 4xx/5xx), but the `/api/takeover/test` handler mapped
  confidence to severity with `== "high" ? high : medium` &mdash; so "possible"
  became a MEDIUM finding rather than being downgraded. A page merely quoting a
  vendor string ("There isn't a GitHub Pages site here.", "NoSuchBucket") was
  flagged. It now maps "possible" (and anything unrecognized) to `info` via the
  pure, unit-tested `severityForTakeoverConfidence` &mdash; a weak lead on an
  explicit test, not a medium alarm, consistent with the passive detector's
  silence on a 200.
- **/audit SSTI battery: any page containing "49" was branded a CRITICAL RCE.**
  The single-shot `{{7*7}}`-style probes reported a critical, RCE-class SSTI
  finding whenever the response contained the arithmetic result (`"49"`), with no
  baseline comparison &mdash; so a page with a `$49` price, a `1949` date, an id,
  or a literal echo of the un-evaluated payload was flagged as remote code
  execution. The battery's own comment promised "require the signature AND that
  it wasn't already in the original response," but the check never did. It now
  fires a benign baseline and confirms only when the result is INTRODUCED by the
  payload (present in the probe, absent from the baseline), via the pure,
  unit-tested `Ssti::sstiEchoConfirms` (mutation-proven).
- **Race-condition probe: a redirect-heavy burst could false-positive as a race.**
  The burst classifier treats transport drops, 429s, 5xx, and unrelated 4xx as
  "noise" that makes a run inconclusive &mdash; but 3xx redirects matched no bucket
  in the status cascade and vanished from the accounting entirely. A burst that
  was mostly 302s (e.g. redirects to a login page) alongside a couple of wins and
  a 409 therefore evaded the inconclusive guard and reported `raceSuspected`. 3xx
  responses now count as noise (a redirect didn't cleanly exercise the contended
  resource), so a redirect-dominated burst is correctly inconclusive. The status
  &rarr; bucket mapping and the win verdict are extracted to pure, unit-tested
  `raceBucketOf()` / `raceIsWin()` (mutation-proven).
- **WebSocket CSWSH probe: a transient reconnect failure could manufacture a
  "confirmed hijack".** After an authenticated cross-origin upgrade is accepted,
  the probe re-issues the same handshake with the credential stripped &mdash; only
  a *refused* baseline confirms the socket honors the session cross-site (CWE-1385).
  The verdict was `!(baseline.status == 101 && baseline.acceptValid)`, which reads
  a transport failure (no response: `ok=false`, `status=0`) as a refusal &mdash; so a
  flaky reconnect (TLS reset, timeout, a server that RSTs the retry) would brand a
  socket a CONFIRMED credentialed hijack. It now requires the baseline to have
  actually responded (`ok`) before treating a non-upgrade as a refusal; an
  ambiguous connection failure grades a LEAD, not a confirmed hijack. The decision
  is extracted to a pure, unit-tested `wsConfirmsHijack()` (mutation-proven: the
  removed guard reintroduces exactly this false positive).
- **WAF fingerprinting: the `Server:`-header Cloudflare signal was dead code.**
  The guard only accepted a `Server` value starting with `cf`, but Cloudflare's
  actual `Server` header is literally `cloudflare` (older edge: `cloudflare-nginx`)
  &mdash; neither starts with `cf`, so this back-up detection path never fired. The
  guard now accepts the real `cloudflare` prefix (keeping a `cf` fallback for any
  cf-branded edge variant). CF-RAY-based detection was unaffected; this only
  restores the secondary signal for responses that carry `Server` but not `CF-RAY`.

### Security
- Mutation-proven regression coverage locked for the WAF/CDN fingerprint family
  (`waf-akamai`, `waf-imperva`, `waf-fastly`, `waf-varnish`, `waf-sucuri`,
  `waf-server-timing`, plus both Cloudflare signals) &mdash; previously only
  `waf-cloudflare` via CF-RAY was tested. Includes discriminating negatives for the
  `Server:` cf-prefix guard and the intentional one-WAF-per-response `break`, so a
  future regression that silently blinds recon to a target's edge protection now
  fails the suite.
- Mutation-proven regression coverage locked for the API-doc/GraphQL-console
  exposure detectors (`swagger-spec`, `openapi-spec`, `graphql-voyager`,
  `graphql-playground`) and the CMS fingerprint family (`cms-joomla`,
  `cms-shopify`, `cms-aem`, `cms-umbraco`, `cms-confluence`, `cms-jira`),
  including negatives that pin the `200`-only exposure gate, the `2xx`&ndash;`3xx`
  CMS gate, and the one-CMS-per-response latch. (These detectors were emitted but
  untested &mdash; a growth of the passive scanner that outran its corpus.)
- **JWT probe acceptance verdict extracted into pure, unit-tested logic.** The
  decision of whether a server *accepted* a forged token (alg:none, weak/blank
  secret, RS256&rarr;HS256 confusion, kid injection) lived in untested inline
  lambdas in `scan()`. It is now `forgeryAccepted` / `corruptLooksAuthorized` /
  `corruptProbeAccepted` in `jwt_probe_logic.cpp`, mutation-proven against the
  exact rules a bug here would break &mdash; the strict-midpoint length tiebreak,
  the 1/8-span "signature-ignored" neighbourhood (the false-positive guard that
  keeps a server which *rejects* bad signatures from being branded forgeable),
  and the forged-rejection baseline gate. Behaviour is unchanged (probe_smoke's
  end-to-end JWT cases still pass); the logic is simply now testable and pinned.
- Exposure scan's soft-404 / catch-all suppression verdict extracted to a pure,
  unit-tested `suppressAsCatchAll()` and mutation-proven. This is the guard that
  decides whether a matched `.env` / `.git/config` / AWS-credentials exposure is
  reported or dropped as a host that 200s every path &mdash; a regression could
  silently drop every real exposure on any SPA/catch-all host (FN) or brand a
  catch-all shell vulnerable (FP). Tests pin the `controlIs2xx` gate, the
  per-signature control re-match, and the `rejectHtml` coupling (an HTML control
  shell never suppresses a plain-text config signature). Behaviour unchanged.
- Deserialization (CWE-502) probe's CONFIRMED verdict extracted to a pure,
  unit-tested `confirmsDeser()` and mutation-proven. The three-shot differential
  (well-formed control clean &rarr; malformed errors &rarr; re-confirm control still
  clean) was composed inline in `test()` and replicated across the
  query/body/cookie/field paths; all four now gate the finding on the one tested
  predicate. Tests pin each guard: the well-formed-clean gate (a shape-WAF that
  errors on valid data must not be branded RCE-vulnerable), the malformed-errors
  detection, and the flap re-confirm (a transient error between shots must not
  false-positive a critical finding). Behaviour unchanged.
- SSRF scan's per-probe CONFIRMED verdict and the IMDS role-name gate extracted
  to pure, unit-tested `ssrfConfirms()` / `isRoleLike()` and mutation-proven.
  Only the shaped-control gate was previously tested; the baseline-absence
  false-positive guard (a signature the target serves unconditionally isn't a
  fetch) and the detection were inline in `confirm()`. `isRoleLike` gates the
  two-step fetch of the critical `aws-imds-iam` AccessKeyId finding &mdash; tests
  pin its `<=128` length boundary and that it accepts legal AWS role characters
  (`+=,.@_-`) so a real role is never silently rejected. Behaviour unchanged.
- CORS reflection derivation extracted to pure, unit-tested `corsNormalizeOrigin`
  / `corsOriginReflected` / `corsHasWildcard` / `corsCredentialsAllowed` and
  mutation-proven. `classifyCorsProbe` (which grades a reflected+credentialed
  origin CRITICAL) was tested, but the derivation of its `reflected` input &mdash;
  the actual "did the server echo our Origin?" decision &mdash; was inline in a
  `test()` the test binary excludes. Tests pin the load-bearing semantics: case-
  fold + trailing-slash normalization (so a re-cased echo isn't a false negative),
  the deliberately-preserved trailing dot (so the trailing-dot host-normalization
  bypass probe still detects a verbatim dotted reflection), and the multi-value
  ACAO scan (a proxy-added second header must not hide a malicious reflection).
  Behaviour unchanged.
- IDOR enumeration verdict's length-tolerance calibration extracted to pure,
  unit-tested `idorTolerance` / `idorDiffersFromNotFound` and mutation-proven.
  `isAccessible` was tested but took `differsFromNotFound` pre-resolved; the
  threshold that produces it &mdash; the boundary between a real distinct object
  and the not-found template &mdash; was inline. Tests pin the `+16` jitter floor
  (so a low-jitter endpoint still needs a real difference), the `qMax` of
  baseline/control jitter (so a token-jittery not-found page widens tolerance and
  is not false-flagged), and the strict `>` boundary. Behaviour unchanged.
- Port scanner's socket-error &rarr; status mapping extracted to a pure,
  unit-tested `portStatusForError()` and mutation-proven. It was inline in the
  socket worker and untested (a different classifier covers the smuggling probe).
  Tests pin that only `HostNotFoundError` sets the host-not-found signal that
  short-circuits the rest of a host's ports &mdash; widening it to a transient
  `NetworkError` would silently skip a live host's remaining open ports (an FN),
  and mapping host-not-found to `filtered` would brand a dead host "up but
  firewalled". Behaviour unchanged.

## [3.8.0] — 2026-08-20

This release folds in a large security-and-correctness pass: a whole-codebase
multi-agent security review (16 findings, from a CRITICAL CI-action fix down to
LOW hardening), two more dead-detector bugs surfaced and fixed by a per-module
detector audit, and mutation-proven regression coverage locked across the passive
scanner's full detector set plus every active-scan probe module. See the
per-entry notes below.

### Added
- **Intercept the response to one specific request.** When you hold a request in
  the intercept editor, you can now forward it and catch just its response &mdash;
  without turning on response interception for everything (Burp's "Do intercept &gt;
  Response to this request"). It's the surgical option: hold a login POST, forward
  it, and see its response, while the flood of other in-scope responses keeps
  flowing untouched. The response is held even with the global response toggle off,
  and only for the request you flagged. (Driven via
  <code class="inline">POST /api/intercept/forward-hold-response</code> for now; the
  right-click menu item in the intercept view is next.)
- **Extensions can hand a request to Repeater or Intruder.** An extension can now
  call <code class="inline">nullock.sendToRepeater(host, port, tls, request)</code>
  or <code class="inline">nullock.sendToIntruder(...)</code> to drop a request it
  built or observed straight into a new Repeater tab or Intruder's base request
  (Burp's send-to-tool). That's the piece that lets an extension kick off a manual
  follow-up &mdash; find something interesting, send it over for hands-on testing
  &mdash; without copy-paste. (Sending to Comparer/Decoder from an extension is
  still to come.)
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
- **Framework fingerprints that key off cookies now scan every Set-Cookie
  header.** The Rails, Laravel, and Django detectors checked only the *first*
  `Set-Cookie` header, but servers emit each cookie in its own header. Rails and
  Laravel missed their session cookie whenever it wasn't first, and Django &mdash;
  which needs both `csrftoken` and `sessionid`, always sent as separate headers
  &mdash; could essentially never fire. All three now scan the joined set of all
  Set-Cookie values, so a realistic multi-cookie response is fingerprinted
  correctly. Covered by a new mutation-proven framework-fingerprint batch (all
  ten previously-untested `fw-*` detectors: Express, Nuxt, AngularJS, React, Vue,
  Rails, Laravel, Django, Symfony, and inlined-initial-state leak).
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
- **Fixed a dead cookie-security detector.** `cookie-secure-prefix-violation`
  (a `__Secure-` prefixed cookie set without the Secure attribute) could never
  fire: the check was `!contains("secure")` against the whole lowercased cookie,
  and a `__Secure-` cookie's name *always* contains the substring "secure", so
  the condition was tautologically false. The `__Host-` check and, in the same
  spirit, could be spoofed by a cookie value containing "secure". Both now match
  an exact tokenized `Secure` attribute (`; secure`), like the adjacent `Path=/`
  check. Locked with a mutation-proven batch that also covers the untested
  `cookie-no-secure` (incl. its TLS-only gate) and `cookie-no-samesite`.
- **Locked the untested HTTP tech-fingerprint header extractors.** The
  `Server` (nginx, IIS, Cloudflare), `X-Powered-By` (PHP, Express, Next.js),
  `X-AspNet-Version`, and `X-Jenkins` version-capture paths had no regression
  coverage &mdash; a broken regex would silently stop fingerprinting the server and
  feed CVE correlation nothing. Added a positive per extractor asserting the
  captured version and CVE kind. Mutation-proven.
- **Locked six untested sensitive-file exposure probes.** The exposure scanner's
  `/.git/HEAD`, `/phpinfo.php`, `/.DS_Store`, `/wp-config.php.bak`,
  `/actuator/env`, and `/config.php.bak` signatures had no regression coverage &mdash;
  a regex/flag regression would silently stop flagging those exposed files. Added
  a positive per probe plus rejectHtml, no-marker, and evidence-redaction
  discriminators. Mutation-proven.
- **Locked eight untested provider patterns in the client-side secret scanner.**
  A separate scanner (`secret_logic`, from the in-page JS secret sweep) had
  coverage for only AWS/JWT/Twilio/assigned secrets; its `github-token`,
  `github-pat`, `google-api-key`, `stripe-secret-key`, `slack-token`,
  `sendgrid-key`, `npm-token`, and `private-key-block` regexes were untested &mdash;
  a regression would silently stop flagging those leaked credentials. Added a
  positive per pattern plus length and placeholder discriminators, mutation-proven.
  Fixtures are assembled from fragments so no literal secret sits in the repo.
- **Locked the last two passive detectors** &mdash; `csv-formula-injection` (a CSV
  cell starting with `=/+/-/@`, an Excel formula-injection vector) and
  `cms-woocommerce` (WooCommerce layered on WordPress). Every kind the passive
  scanner can emit now has mutation-proven regression coverage.
- **Locked five request/method/caching detectors.** `secret-in-url` (a
  sensitive query param), `debug-method-allowed` (an accepted TRACE/CONNECT/
  PROPFIND), `cache-vary-missing-cookie` (a cookie-setting cacheable 200 with no
  `Vary: Cookie`), `server-timing-leak`, and `options-mutation-methods` gained
  positive + negative coverage, including the TRACE-must-be-2xx and Vary:Cookie
  discriminators. Mutation-proven. This completes regression coverage for the
  passive scanner's full detector set.
- **Locked four content-leak detectors.** `mixed-content` (an HTTPS page
  referencing `http://` resources), `internal-hostname-leak` (an internal-TLD
  hostname in the body), `html-comment-leak` (TODO/FIXME/password/etc. in an HTML
  comment), and `robots-discloses-paths` (sensitive paths in robots.txt) gained
  positive + negative coverage, including the robots.txt path gate. Mutation-proven.
- **Locked the GraphQL/gRPC protocol detectors.** `protocol-grpc`,
  `protocol-graphql`, and `graphql-introspection` gained positive + negative
  coverage, pinning that only `__schema` (not the ubiquitous `__typename`) marks
  introspection as enabled and that a non-GraphQL JSON path stays quiet.
  Mutation-proven.
- **Locked four server/stack info-disclosure detectors.** `source-map-exposed`
  (a production JS `sourceMappingURL`), `phpinfo-output` (a reachable phpinfo()
  page &mdash; critical), `server-version-leak` (a versioned `Server` header), and
  `x-powered-by` gained positive + negative coverage, pinning phpinfo's
  three-marker AND and that a bare `Server` product name (no `/version`) is not a
  leak. Mutation-proven.
- **Locked the redirect / Host-header-reflection detectors.**
  `open-redirect-suspect` (a 3xx whose cross-host Location host is echoed from a
  request query param) and `host-header-reflected-location` (the Host value
  reflected into an absolute Location &mdash; password-reset-poisoning surface)
  gained positive + negative coverage, pinning the cross-host + query-derivation
  requirement and the schemeless-Location skip. Mutation-proven.
- **Locked the two JWT-leakage detectors.** `jwt-in-url` (a JWT-shape token in
  the request path &mdash; logged in proxies, referrers, history) and
  `jwt-echoed-in-body` (a JWT reflected in a non-auth response body) gained
  positive + negative coverage, including the 3-segment shape requirement and the
  login/auth/token path suppression. Mutation-proven; fixtures built from
  fragments so no full JWT-shape literal sits in the repo.
- **Locked HSTS-strength and auth-hygiene detectors.** `hsts-no-subdomains`,
  `hsts-no-preload`, `auth-over-http` (an Authorization header on plaintext), and
  `auth-no-cache-control` (an authenticated 200 cacheable by shared proxies) gained
  positive + negative coverage, including their gates: HSTS strength only on TLS,
  auth-over-http only on plaintext, auth-no-cache only when authenticated. Mutation-proven.
- **Locked four untested cross-origin-isolation-header detectors.**
  `missing-permissions-policy`, `missing-coop`, `missing-coep`, and
  `missing-corp` gained positive + header-present-negative coverage, plus gate
  negatives (a JSON body or a 5xx response must not fire) and the legacy
  `Feature-Policy` fallback for permissions-policy. Mutation-proven.
- **Locked three untested deserialization-gadget detectors.** `deser-pickle`
  (Python), `deser-ruby` (Marshal), and `deser-dotnet` (BinaryFormatter) &mdash;
  HIGH `gadget-chain RCE candidate` findings keyed off a base64 magic prefix in
  the request body &mdash; had no coverage. Added a positive per language plus a
  one-char-off near-miss negative each (e.g. pickle matches `gASV` but not
  `gASX`), pinning the deliberately narrow needles. Mutation-proven.
- **Locked four untested CSP-weakness detectors.** `csp-unsafe-eval`,
  `csp-wildcard-src`, `csp-no-form-action`, and `csp-no-base-uri` gained
  positive + discriminating-negative coverage &mdash; including that a wildcard
  *subdomain* (`*.host`) is not the bare any-origin `*` the wildcard check flags.
  Mutation-proven so a directive-parsing regression can't silently pass a weak CSP.
- **Locked all four CORS-misconfiguration detectors.** `cors-wildcard`,
  `cors-wildcard-creds`, `cors-methods-wildcard`, and `cors-headers-wildcard`
  had no regression coverage &mdash; a condition regression could have silently
  stopped flagging an `ACAO: *` with `Allow-Credentials: true` (a genuine
  cross-origin exposure). Added positive + discriminating-negative cases that
  pin the wildcard/credentials if-else mutual exclusivity; mutation-proven.
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
