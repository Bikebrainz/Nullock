# Create static library for Proxy
add_library(Proxy STATIC
    proxy_server.cpp
    proxy_server.hpp
    cert_authority.cpp
    cert_authority.hpp
    intercept.cpp
    intercept.hpp
    http2_client.cpp
    http2_client.hpp
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

# Include directories
target_include_directories(Proxy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
