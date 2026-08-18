# tls_accept_logic.cpp is the pure upstream-cert accept filter (QSslError only).
# Compile it directly into the test (same self-validating pattern as
# intercept_logic) so a regression in the benign-error allowlist is caught here.
# QSslError lives in Qt6::Network, so this links Core + Network (no proxy socket
# machinery is pulled in -- tls_accept_logic.cpp has no other dependency).
add_executable(tls_accept_logic_test
    tls_accept_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/tls_accept_logic.cpp
)

target_link_libraries(tls_accept_logic_test PRIVATE
    Qt6::Core
    Qt6::Network
)

target_include_directories(tls_accept_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME tls_accept_logic COMMAND tls_accept_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET tls_accept_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:tls_accept_logic_test>/Qt6Core${_d}.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Network${_d}.dll"
            "$<TARGET_FILE_DIR:tls_accept_logic_test>/Qt6Network${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
