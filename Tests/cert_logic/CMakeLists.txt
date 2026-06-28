# cert_logic.cpp is the pure MITM-CA host-injection guard (QString only -- no
# QProcess/QFile/Win32) but lives in the heavy Proxy lib. Compile it DIRECTLY into
# the test so the binary links Qt6::Core alone. (This also recompiles cert_logic.cpp.)
add_executable(cert_logic_test
    cert_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/cert_logic.cpp
)

target_link_libraries(cert_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(cert_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME cert_logic COMMAND cert_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET cert_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:cert_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
