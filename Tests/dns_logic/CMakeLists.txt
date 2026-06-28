# dns_logic.cpp is the pure DNS-query wire parser (QByteArray/QString/QRegularExpression
# only -- no QUdpSocket/QObject). Compile it DIRECTLY into the test so the binary
# links Qt6::Core alone. This also recompiles dns_logic.cpp, so the test
# self-validates its compilation.
add_executable(dns_logic_test
    dns_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast/dns_logic.cpp
)

target_link_libraries(dns_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(dns_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast
)

add_test(NAME dns_logic COMMAND dns_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET dns_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:dns_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
