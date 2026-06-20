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
