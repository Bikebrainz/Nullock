# Find testing framework
find_package(Qt6 REQUIRED COMPONENTS Test)

# Create test executable (add test files as needed)
add_executable(NullockTests)

# Add test source files
target_sources(NullockTests PRIVATE
    # test code files here
    test.cpp
)

# Link libraries for testing
target_link_libraries(NullockTests PRIVATE
    Qt6::Test
    AppController
    Database
    Networking
)

# Register tests
add_test(NAME NullockTests COMMAND NullockTests)

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
