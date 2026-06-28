add_executable(scan_bridge_test
    scan_bridge_test.cpp
)

# scan_bridge is entirely pure (port-scan results -> findings; no network), so the
# test links its object plus service_vulns_logic (the curated CVE table it calls)
# against Qt6::Core alone. port_scanner.hpp (for PortResult) is Core-only -- no
# QtNetwork -- so linking Networking pulls just those objects, NOT the scanner's
# QTcpSocket I/O.
target_link_libraries(scan_bridge_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(scan_bridge_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME scan_bridge COMMAND scan_bridge_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET scan_bridge_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:scan_bridge_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
