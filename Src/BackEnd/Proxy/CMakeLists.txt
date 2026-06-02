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
    websocket.cpp
    websocket.hpp
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
