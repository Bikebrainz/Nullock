# Create static library for Networking
add_library(Networking STATIC
    networking.cpp
    networking.hpp
)

# Link Qt libraries
target_link_libraries(Networking PRIVATE
    Qt6::Core
    Qt6::Network
)

# Include directories
target_include_directories(Networking PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
