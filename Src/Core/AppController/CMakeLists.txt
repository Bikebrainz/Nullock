# Create static library for AppController
add_library(AppController STATIC
    app_controller.cpp
    app_controller.hpp
)

# Link Qt libraries
target_link_libraries(AppController PRIVATE
    Qt6::Core
    Qt6::Gui
)

# Include directories
target_include_directories(AppController PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
