# Create static library for Cache
add_library(Cache STATIC
    cache_handler.cpp
    cache_handler.hpp
)

# Link Qt libraries
target_link_libraries(Cache PRIVATE
    Qt6::Core
)

# Include directories
target_include_directories(Cache PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
