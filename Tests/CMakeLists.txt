# Find testing framework
find_package(Qt6 REQUIRED COMPONENTS Test)

# (The original NullockTests placeholder was removed: it asserted only
# QVERIFY(true) and linked a library that had been renamed -- `Database`, now
# `Storage` -- so it no longer built (LNK1181) and was excluded from CI. The
# real coverage lives in the standalone suites below.)

# Scanner regression corpus -- exercises every passive detector with
# positive + negative cases. Run via: ctest -R scanner_regression -V
add_subdirectory(scanner_regression)

# CVE-correlation corpus -- locks in version->CVE accuracy (per-branch
# ranges, CVSS scores, removed entries). Run via: ctest -R cve_database -V
add_subdirectory(cve_database)

# Finding-enricher coverage -- every emitted finding kind must map to a
# non-empty CWE/OWASP. Run via: ctest -R finding_enricher -V
add_subdirectory(finding_enricher)

# RequestExport -- CSRF PoC + copy-as-curl transforms (escaping/structure).
# Run via: ctest -R request_export -V
add_subdirectory(request_export)

# Intruder engine -- attack-type combination generation + marker substitution.
# Run via: ctest -R intruder_engine -V
add_subdirectory(intruder_engine)

# CORS tester -- the registrable-domain heuristic, the suffix-domain /
# trailing-dot probe battery, and buildRequest's CR/LF guards (pure logic).
# Run via: ctest -R cors_tester -V
add_subdirectory(cors_tester)

# Open redirect -- browser-style host resolution, the hardened client-side
# (meta/JS) detector, and buildRequest's CR/LF guards (pure logic).
# Run via: ctest -R open_redirect -V
add_subdirectory(open_redirect)

# SSTI -- the two-expression confirmation (template vs calculator), locale
# digit-grouping, all-region scan, and buildRequest's CR/LF guards (pure logic).
# Run via: ctest -R ssti_tester -V
add_subdirectory(ssti_tester)

# Command injection -- the command-substitution proof (exec vs arithmetic),
# all-region scan, and buildRequest's CR/LF guards (pure logic).
# Run via: ctest -R cmd_injection -V
add_subdirectory(cmd_injection)

# Host header -- URL-context detection (quoted/unquoted // vs prose) and
# buildRequest's CR/LF guards (pure logic).
# Run via: ctest -R host_header -V
add_subdirectory(host_header)

# XXE -- the inert-DOCTYPE-controlled confirmation (real read vs disallow-doctype
# error page), file-content signatures, and buildRequest's CR/LF guards.
# Run via: ctest -R xxe_injection -V
add_subdirectory(xxe_injection)

# NoSQL injection -- the 2x2 differential (two always-true ops agree while $eq
# tracks the literal) and buildRequest's CR/LF guards (pure logic).
# Run via: ctest -R nosql_injection -V
add_subdirectory(nosql_injection)

# LDAP injection -- error signatures (generic vs engine-specific), the WAF
# block-status guard, and buildRequest's CR/LF guards (pure logic).
# Run via: ctest -R ldap_injection -V
add_subdirectory(ldap_injection)

# XPath injection -- error signatures (generic vs engine-specific), the WAF
# block-status guard, and buildRequest's CR/LF guards (pure logic).
# Run via: ctest -R xpath_injection -V
add_subdirectory(xpath_injection)

# SQL injection -- DBMS error signatures (generic vs specific), the WAF
# block-status guard, and buildRequest's CR/LF guards (pure logic).
# Run via: ctest -R sql_injection -V
add_subdirectory(sql_injection)

# Path traversal -- file-content signatures and buildRequest's CR/LF guards
# (pure logic; the shaped-control FP guard is covered live in probe_smoke).
# Run via: ctest -R path_traversal -V
add_subdirectory(path_traversal)

# Cache poisoning -- the FAIL-CLOSED safety gate (silent cache / failed-confirm
# / unkeyed buster all abort), reflection-surface filtering (Set-Cookie
# excluded), the Vary-on-injected-header cacheability downgrade, and
# buildRequest's CR/LF guards (pure logic; live flow covered in probe_smoke).
# Run via: ctest -R cache_poison -V
add_subdirectory(cache_poison)

# Cache deception -- the inert catch-all control that suppresses SPA / soft-200
# false positives, the tightened length-similarity test, and buildGet's CR/LF
# guards (pure logic; live flow covered in probe_smoke).
# Run via: ctest -R cache_deception -V
add_subdirectory(cache_deception)

# IDOR / BOLA -- the fail-closed control gate, the enumeration-lead
# classification, zero-padding-preserving neighbor generation, id substitution,
# and buildRequest's CR/LF guards (pure logic; live flow covered in probe_smoke).
# Run via: ctest -R idor_tester -V
add_subdirectory(idor_tester)

# Verb tampering -- the override-redundancy de-dup, HEAD Content-Length
# corroboration, case-variant generation, and buildRequest's CR/LF guards
# (pure logic; live flow covered in probe_smoke).
# Run via: ctest -R verb_tamper -V
add_subdirectory(verb_tamper)

# Mass assignment -- the 2xx accepted-status gate (a marker echoed in a 4xx
# validation error is not a bind), JSON/form sniffing, and buildRequest's CR/LF
# guards (pure logic; live flow covered in probe_smoke).
# Run via: ctest -R mass_assign -V
add_subdirectory(mass_assign)

# Prototype pollution -- the structural exactly-N-space indent anchor, JSON
# sniffing, the compressed-body inconclusive gate, and buildGet/buildPollute's
# CR/LF guards (pure logic; the live causal proof + constructor.prototype
# fallback are covered in probe_smoke).
# Run via: ctest -R proto_pollution -V
add_subdirectory(proto_pollution)

# Insecure deserialization -- the engine-specific error signatures (and the
# bare-API-name non-matches), the framework-carrier ordering that survives the
# param cap, queryWith, and the four builders' CR/LF guards (pure logic; the
# well-formed/malformed differential across transports is covered in probe_smoke).
# Run via: ctest -R deser_probe -V
add_subdirectory(deser_probe)

# Subdomain takeover -- branded fingerprints fire while the pruned generic 404
# strings (stock Apache 404, bare "Repository not found", "project not found")
# do NOT, and buildGet's CR/LF guards (pure logic; live flow in probe_smoke).
# Run via: ctest -R takeover_scan -V
add_subdirectory(takeover_scan)

# Race tester -- the burst verdict (raceSuspected needs a 409/422 contention
# rejection, not any 4xx; over-grant when all writes win; noise-inconclusive)
# and buildRequest's CR/LF guards (pure logic; the concurrent burst is I/O).
# Run via: ctest -R race_tester -V
add_subdirectory(race_tester)

# Param miner -- the status-flip re-confirmation (defeats a transient flap),
# reflection in body OR header, and buildRequest's CR/LF + duplicate-header
# guards (pure logic; the batch/bisection walk is I/O, covered in probe_smoke).
# Run via: ctest -R param_miner -V
add_subdirectory(param_miner)

# Exposure scan -- the tightened signatures (.env case-sensitive + >=2 lines,
# config files reject an HTML shell), evidence redaction, and buildGet's CR/LF
# guards (pure logic; the live soft-404 calibration is covered in probe_smoke).
# Run via: ctest -R exposure_scan -V
add_subdirectory(exposure_scan)

# Secret scanner -- the placeholder/entropy filter now applied to EVERY match
# (documented example keys dropped), the assigned-secret '=' fix, severity
# downgrades, masking, and buildGet's CR/LF guards (pure logic; the live
# fetch + same-origin script follow is I/O).
# Run via: ctest -R secret_scanner -V
add_subdirectory(secret_scanner)

# HTTP fingerprint -- the detect() table: a CVE-bearing version attaches ONLY
# from a distinctive marker (Joomla/Drupal generator-meta, not free body text),
# Django requires both cookies, and buildGet's CR/LF guards (pure logic;
# the single GET is I/O).
# Run via: ctest -R http_fingerprint -V
add_subdirectory(http_fingerprint)

# WAF / CDN / LB detection -- the passive signature matcher: per-vendor
# positives across all three match styles (header-presence / header-value
# substring / cookie-NAME), strongest-first dedup-by-name (cf-ray beats
# Server: cloudflare), cookie matching on NAME only (a needle in a cookie
# value/attribute must NOT fire), case-insensitivity, and buildGet's CR/LF
# guards (pure logic; the single GET is I/O).
# Run via: ctest -R waf_detect -V
add_subdirectory(waf_detect)

# Reflected XSS -- inExecutingHtmlContext, the reduced HTML5 tokenizer deciding
# whether a reflected <marker> runs: attribute-quote tracking (a '>' inside a
# quoted value must NOT end the tag -- the headline FP), raw-text elements incl.
# plaintext/noframes/noembed, "</name"+delimiter and "--!>" close variants,
# multi-occurrence + case-insensitive detection, isHtmlContentType, queryWith,
# and buildRequest's CR/LF guards (pure logic; the sends are I/O).
# Run via: ctest -R xss_reflected -V
add_subdirectory(xss_reflected)

# CRLF / HTTP response splitting -- splitConfirmed: a parsed planted header OR a
# colon-less split line at a header-block boundary confirms (the server decoded
# CR/LF but not %3a), while a body echo or a mid-line reflection does NOT (no
# FP); queryWith splices the raw payload without re-encoding; buildRequest's
# CR/LF guards on method/host/basePath/query (pure logic; the sends are I/O).
# Run via: ctest -R crlf_injection -V
add_subdirectory(crlf_injection)

# HTTP method audit -- parseAllow (dedup/upper/trim of the Allow header), the
# dangerous write/WebDAV subsets, traceEchoed (XST needs BOTH the TRACE token
# and our UA, so a page mentioning "trace" can't trip it), and buildReq's CR/LF
# guards on method/host/basePath/query (pure logic; OPTIONS/TRACE are I/O).
# Run via: ctest -R method_audit -V
add_subdirectory(method_audit)

# Security-header / CSP audit -- the pure analyzer: a CSP with no script-src and
# no default-src is script-unrestricted (csp-no-script-restriction), scheme-
# prefixed wildcards (https://*) are flagged, HSTS max-age=0/invalid is distinct
# from a short window, only DENY/SAMEORIGIN X-Frame-Options and a restrictive
# ENFORCED frame-ancestors protect, a malformed 'sha token doesn't suppress
# unsafe-inline, hostMatches' dot-guard, and buildRequest's CR/LF guards.
# Run via: ctest -R header_audit -V
add_subdirectory(header_audit)

# Token-randomness sequencer -- the verdict is driven by EFFECTIVE keyspace
# (bits/symbol * length), so a short hex token is brute-forceable however flat
# its bytes while a long hex token is strong; base-auto-detected sequential
# counters (incl. the 99->100 carry), the n=3 delta-threshold FP, strictly-
# monotonic timestamps, and the constant-prefix LCS strip (pure logic).
# Run via: ctest -R sequencer -V
add_subdirectory(sequencer)

# Port scanner banner classifier -- an OS mention isn't a service (no
# winrm/smb from "Microsoft Windows"), an HTML body mentioning a DB is HTTP
# (HTTP/1. status line wins before the DB substring matches), IMAP "* OK" is
# detected without the literal word, dev/app-server ports classify http, and
# TLS is read from the RAW 0x16 0x03 record bytes (pure logic; sockets are I/O).
# Run via: ctest -R port_scanner -V
add_subdirectory(port_scanner)

# HttpClient transport-outcome classifier -- classifySocketOutcome maps a failed
# socket's error()/state() to {Ok,Timeout,Reset,ConnectError}. Locks the property
# the smuggling FP fix depends on: a read TIMEOUT (socket open & silent -- a true
# desync block) is distinct from a RESET/connect error (a hold-then-RST WAF
# quarantine that mimics the same delay), and no reset/connect error ever grades
# as Timeout (pure enum mapping; the live 15s read path can't be unit-timed).
# Run via: ctest -R networking -V
add_subdirectory(networking)

# HTTP request smuggling -- the byte-exact probe builders: CL.TE (CL=6 + chunked
# + "1\r\nA\r\nX"), TE.CL (CL=6 + chunked + "0\r\n\r\nX"), the valid-ambiguous
# control (CL=5 + "0\r\n\r\n", strands neither parser), Connection: close on
# every probe, caller CL/TE stripped, and a CR/LF basePath/host aborting the
# build (a wrong byte silently makes the probe inert -- pure logic; timing I/O).
# Run via: ctest -R smuggling -V
add_subdirectory(smuggling)

# CSWSH WebSocket probe -- expectedAccept against the RFC 6455 known vector
# (key dGhlIHNhbXBsZSBub25jZQ== -> s3pPLMBiTxaQ9kYGzzhZRbK+xOo=), headerValue's
# colon-anchoring / case handling, statusFromHeaderBlock, buildHandshake (the
# upgrade headers, Origin present/omitted, carried-header strip, CR/LF abort),
# and hasCredential (gates a CONFIRMED hijack vs an Origin-not-validated lead).
# Run via: ctest -R ws_probe -V
add_subdirectory(ws_probe)

# TLS inspector pure logic -- the algorithm-aware key-strength gate (a 256-bit EC
# key is NOT weak), RFC 6125 hostname matching (SAN precedence over CN, single-
# label wildcard, trailing-dot FQDN normalization), negotiated-cipher
# classification (NULL/anon/EXPORT/RC4/DES vs 3DES/MD5 legacy), and over-broad
# public-suffix wildcard detection. Links tls_logic.cpp against Qt6::Core alone.
# Run via: ctest -R tls_inspect -V
add_subdirectory(tls_inspect)

# TLS-profile (browser-mimic ClientHello shaping) pure logic: the name<->profile
# mapping, the browser cipher lists, and the TLS-1.3-suite split that gates the
# partial-cipher-list soundness fix. Links tls_profile_logic.cpp against Qt6::Core.
# Run via: ctest -R tls_profile -V
add_subdirectory(tls_profile)

# Content-discovery soft-404 classification -- same-depth calibration, the
# softStatuses-set model, redirect-Location discrimination (a dir-redirect to a
# different target is reported, not masked by a redirect-soft-404), 401/403
# body-size discrimination, and WAF-saturation detection. Links content_logic.cpp
# against Qt6::Core alone.
# Run via: ctest -R content_discovery -V
add_subdirectory(content_discovery)

# Crawler pure logic -- the FAIL-CLOSED default scope (an unconfigured crawl
# stays in the seed's domain tree, never walks arbitrary hosts), <base href>
# resolution, quoted+unquoted link extraction, the http(s)-only canonicalizer
# (rejects mailto:/javascript:/data:, normalizes the apex), and tag-boundary body
# truncation. Links crawler_logic.cpp against Qt6::Core alone.
# Run via: ctest -R crawler -V
add_subdirectory(crawler)

# robots.txt / sitemap parsing -- Disallow path-vs-pattern classification (a
# wildcard "/*.php$" is not a fetchable path), absolute-URL Disallow drop,
# namespaced/attributed <loc> extraction (<image:loc>, <loc xml:lang=...>),
# sitemap-index detection, and the line-leading-directive guard. Links
# robots_logic.cpp against Qt6::Core alone.
# Run via: ctest -R robots_recon -V
add_subdirectory(robots_recon)

# Recon-engine pure helpers -- crt.sh name canonicalization (strip ALL leading
# "*."), the acceptCertName filter (drop apex-collapse + residual wildcards), the
# search-domain answer-record guard, and the wildcard-DNS false-positive
# suppression decision. Links recon_logic.cpp against Qt6::Core alone.
# Run via: ctest -R recon_engine -V
add_subdirectory(recon_engine)

# jwt_tool offline decode + weakness analysis -- unparseable-payload handling (no
# fabricated jwt-no-exp), string-encoded exp, absent-alg vs the 'none' bypass,
# the RS/ES/PS alg-confusion lead, the kid allow-list, all-privilege-claims, JWE
# rejection, and HMAC-only bruteHmac. jwt_tool is Qt6::Core-only.
# Run via: ctest -R jwt_tool -V
add_subdirectory(jwt_tool)

# JS-recon endpoint mining -- path-segment-anchored API tokens (no /therapist/
# false positives), relative paths, modern call shapes (import/Worker/sendBeacon/
# WebSocket) + ws(s), xhr.open URL-not-verb, template-literal prefixes, host-suffix
# CDN filtering, and last-wins sourceMappingURL. js_recon_logic.cpp is Qt6::Core-only.
# Run via: ctest -R js_recon -V
add_subdirectory(js_recon)

# Session-handling rule logic -- the inject sanitizers (CR/LF strip for headers,
# ';'-strip for cookies, JSON-escape for JSON bodies), exact-integer JSON numerics,
# first-segment cookie extraction, first-participating regex group, and pathGlob
# query stripping. session_rules_logic.cpp is Qt6::Core-only.
# Run via: ctest -R session_rules -V
add_subdirectory(session_rules)

# Service-version CVE matcher -- parseBanner per-product regexes, the version
# range math (min incl / max EXCL / exact) at the boundary conditions, and the
# precision-aware grading: a truncated "Apache/2.4" still matches a 2.4.x range
# CVE but is flagged a LEAD (precise=false), not a confirmed critical, because
# its hidden patch level might be fixed; plus the overlay dedup-by-cveId.
# Run via: ctest -R service_vulns -V
add_subdirectory(service_vulns)

# Active JWT probe -- the pure forgery/request builders: corruptSignature flips
# one DECODED signature byte (avoids the base64-padding round-trip that re-
# accepts ~1/16 of tokens) and adds a junk sig to a no-sig token; algNoneVariants
# emits the 6 none/None/NONE/nOnE/empty/absent bypass tokens; buildRequest's
# Authorization/header/cookie carriers, the no-token credential-drop, and CR/LF
# guards on every field (links the pure jwt_tool; testOneCarrier is I/O).
# Run via: ctest -R jwt_probe -V
add_subdirectory(jwt_probe)
