# Create single shared library for all APIs
add_library(APIs SHARED
    ExtensionsAPI/extensions_api.cpp
    ExtensionsAPI/extensions_api.hpp
    ManagerAPI/manager_api.cpp
    ManagerAPI/manager_api.hpp
)

# Link Qt libraries
target_link_libraries(APIs PRIVATE
    Qt6::Core
    Qt6::Network
)

# Include directories
target_include_directories(APIs PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Set library properties
set_target_properties(APIs PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
)
