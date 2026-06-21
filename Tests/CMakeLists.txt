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
