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
