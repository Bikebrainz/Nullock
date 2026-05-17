# Create static library for Proxy
add_library(Proxy STATIC
    proxy_server.cpp
    proxy_server.hpp
)

# Link Qt libraries
target_link_libraries(Proxy PRIVATE
    Qt6::Core
    Qt6::Network
)

# Include directories
target_include_directories(Proxy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
