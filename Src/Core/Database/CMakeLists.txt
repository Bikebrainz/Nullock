# Create static library for Database
add_library(Database STATIC
    database_manager.cpp
    database_manager.hpp
)

# Link Qt libraries
target_link_libraries(Database PRIVATE
    Qt6::Core
)

# Include directories
target_include_directories(Database PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
