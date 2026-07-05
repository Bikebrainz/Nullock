# Create static library for Proxy
add_library(Proxy STATIC
    proxy_server.cpp
    proxy_server.hpp
    proxy_logic.cpp
    proxy_logic.hpp
    cert_authority.cpp
    cert_authority.hpp
    cert_logic.cpp
    cert_logic.hpp
    intercept.cpp
    intercept.hpp
    intercept_logic.cpp
    intercept_logic.hpp
    http2_client.cpp
    http2_client.hpp
    h2_client_logic.cpp
    h2_client_logic.hpp
    h2_server_logic.cpp
    h2_server_logic.hpp
    h2_server.cpp
    h2_server.hpp
    websocket.cpp
    websocket.hpp
    ws_repeater.cpp
    ws_repeater.hpp
    http1_parser.hpp
    h2_events.cpp
    h2_events.hpp
    h2_logic.cpp
    h2_logic.hpp
)

# nghttp2 lives at D:/vcpkg/installed/x64-windows. There's no CMake config
# file shipped, so we point at the lib and include dir directly. If this
# tree gets relocated, override NULLOCK_NGHTTP2_ROOT from the configure.
if(NOT DEFINED NULLOCK_NGHTTP2_ROOT)
    set(NULLOCK_NGHTTP2_ROOT "D:/vcpkg/installed/x64-windows")
endif()
target_include_directories(Proxy PRIVATE "${NULLOCK_NGHTTP2_ROOT}/include")
target_link_libraries(Proxy PRIVATE "${NULLOCK_NGHTTP2_ROOT}/lib/nghttp2.lib")

# Qt6::Network is PUBLIC because proxy_server.hpp uses QHostAddress in its
# public API, so anyone who links Proxy needs the Network includes too.
target_link_libraries(Proxy PUBLIC
    Qt6::Core
    Qt6::Network
)
# proxy_server.cpp includes extensions_api.hpp which pulls in QJSEngine for
# its handler list. Qml stays PRIVATE because it's an implementation detail
# of the mutation call -- the Proxy public API doesn't expose any Qml type.
target_link_libraries(Proxy PRIVATE Qt6::Qml)

# websocket.cpp inflates permessage-deflate (RFC 7692) frames for display using
# the zlib bundled inside Qt6Core. Qt6::ZlibPrivate is an INTERFACE target: it
# only supplies the <zlib.h> include dir + the QT_ZLIB_LIB define. The actual
# z_inflate* symbols are already exported by Qt6::Core (linked above), which is
# why no separate zlib library is needed.
find_package(Qt6 REQUIRED COMPONENTS ZlibPrivate)
target_link_libraries(Proxy PRIVATE Qt6::ZlibPrivate)

# Include directories
target_include_directories(Proxy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# proxy_server.cpp pulls in extensions_api.hpp to call applyRequestMutation /
# applyResponseMutation. Only the .cpp needs it (the .hpp uses just a fwd
# declaration), so PRIVATE include of the ExtensionsAPI source dir is enough
# and avoids dragging Qml into Proxy's public dependency surface.
target_include_directories(Proxy PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/ExtensionsAPI
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)
