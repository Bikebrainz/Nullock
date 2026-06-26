add_executable(ws_probe_test
    ws_probe_test.cpp
)

# Exercises only the pure logic (expectedAccept, headerValue,
# statusFromHeaderBlock, buildHandshake) which lives in ws_logic.cpp and depends
# on Qt6::Core alone. Linking Networking pulls just that object -- NOT
# ws_probe.cpp's handshake() (QSslSocket/QTcpSocket) -- so the binary stays free
# of the Network/Qml/GUI chain.
target_link_libraries(ws_probe_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(ws_probe_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME ws_probe COMMAND ws_probe_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET ws_probe_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:ws_probe_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
