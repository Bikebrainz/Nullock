# Create static library for Nullem
add_library(Nullem STATIC
    nullem.cpp
    nullem.hpp
)

# Link Qt libraries
target_link_libraries(Nullem PRIVATE
    Qt6::Core
)

# Include directories
target_include_directories(Nullem PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
