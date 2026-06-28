# websocket.cpp is a pure RFC 6455 frame parser (QByteArray/QList only -- no
# QtNetwork) but lives in the heavy Proxy lib (nghttp2/Qml/Network). Compile it
# DIRECTLY into the test so the binary links Qt6::Core alone, avoiding the whole
# proxy link chain. (This also means the test itself recompiles websocket.cpp.)
add_executable(websocket_test
    websocket_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/websocket.cpp
)

target_link_libraries(websocket_test PRIVATE
    Qt6::Core
)

target_include_directories(websocket_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME websocket COMMAND websocket_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET websocket_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:websocket_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
