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
    content_decode.cpp
    content_decode.hpp
    ws_repeater.cpp
    ws_repeater.hpp
    http1_parser.hpp
    h2_events.cpp
    h2_events.hpp
    h2_logic.cpp
    h2_logic.hpp
)

# nghttp2. On Windows it comes from vcpkg (no CMake config shipped, so point at
# the import lib + include dir directly; override NULLOCK_NGHTTP2_ROOT to relocate).
# On Linux/macOS it's the system package (apt libnghttp2-dev / brew nghttp2),
# found via pkg-config -- the hardcoded vcpkg .lib path is Windows-only and a
# raw Windows path fed to ld/clang breaks the non-Windows link.
if(WIN32)
    if(NOT DEFINED NULLOCK_NGHTTP2_ROOT)
        set(NULLOCK_NGHTTP2_ROOT "D:/vcpkg/installed/x64-windows")
    endif()
    target_include_directories(Proxy PRIVATE "${NULLOCK_NGHTTP2_ROOT}/include")
    target_link_libraries(Proxy PRIVATE "${NULLOCK_NGHTTP2_ROOT}/lib/nghttp2.lib")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2)
    target_link_libraries(Proxy PRIVATE PkgConfig::NGHTTP2)
endif()

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
# Windows Qt bundles zlib and ships Qt6::ZlibPrivate (the <zlib.h> include +
# Z_PREFIX define; the z_* symbols come from Qt6::Core). Linux/macOS Qt is built
# against the SYSTEM zlib and does NOT ship that private config, so fall back to
# the system zlib there. Either way <zlib.h> + inflate*/deflate* resolve for
# websocket.cpp (permessage-deflate) and content_decode.cpp (Content-Encoding).
find_package(Qt6 QUIET OPTIONAL_COMPONENTS ZlibPrivate)
if(TARGET Qt6::ZlibPrivate)
    target_link_libraries(Proxy PRIVATE Qt6::ZlibPrivate)
else()
    find_package(ZLIB REQUIRED)
    target_link_libraries(Proxy PRIVATE ZLIB::ZLIB)
endif()

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
