# websocket.cpp is the RFC 6455 frame parser + the RFC 7692 permessage-deflate
# inflater. It lives in the heavy Proxy lib (nghttp2/Qml/Network) but only needs
# QByteArray + zlib, so compile it DIRECTLY into the test -- the binary links
# Qt6::Core alone, avoiding the whole proxy link chain. (This also recompiles
# websocket.cpp for the test.) The z_inflate*/z_deflate* symbols it uses are
# exported by Qt6Core; Qt6::ZlibPrivate only adds the <zlib.h> include dir.
add_executable(websocket_test
    websocket_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/websocket.cpp
)

find_package(Qt6 REQUIRED COMPONENTS ZlibPrivate)
target_link_libraries(websocket_test PRIVATE
    Qt6::Core
    Qt6::ZlibPrivate
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
