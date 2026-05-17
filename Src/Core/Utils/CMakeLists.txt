# Create static library for Utils
add_library(Utils STATIC)

# Include directories for utility headers
target_include_directories(Utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link Qt libraries
target_link_libraries(Utils PRIVATE
    Qt6::Core
)
