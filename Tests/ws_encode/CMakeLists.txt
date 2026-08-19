# ws_encode.cpp is the pure WebSocket frame serializer + hold-eligibility (no zlib,
# no sockets). Compile it directly into the test (same self-validating pattern as
# intercept_logic) so a framing/masking regression is caught here. Links Qt6::Core
# alone (QRandomGenerator + QByteArray).
add_executable(ws_encode_test
    ws_encode_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/ws_encode.cpp
)

target_link_libraries(ws_encode_test PRIVATE
    Qt6::Core
)

target_include_directories(ws_encode_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME ws_encode COMMAND ws_encode_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET ws_encode_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:ws_encode_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
