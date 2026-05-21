# Create static library for Proxy
add_library(Proxy STATIC
    proxy_server.cpp
    proxy_server.hpp
    cert_authority.cpp
    cert_authority.hpp
)

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
