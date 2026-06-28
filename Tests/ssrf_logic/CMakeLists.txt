# ssrf_logic.cpp is the pure SSRF request builder (QByteArray/QString only -- no
# HttpClient / network). Compile it DIRECTLY into the test so the binary links
# Qt6::Core alone (ssrf_scan.cpp's test() pulls the Networking I/O stack). It pulls
# ssrf_scan.hpp for the Request struct, which is plain Qt6::Core structs.
add_executable(ssrf_logic_test
    ssrf_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/ssrf_logic.cpp
)

target_link_libraries(ssrf_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(ssrf_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME ssrf_logic COMMAND ssrf_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET ssrf_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:ssrf_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
