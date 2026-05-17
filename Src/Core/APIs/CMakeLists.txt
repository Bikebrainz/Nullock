# APIs is STATIC for now because the source files are stubs and MSVC will
# not emit an import .lib for a SHARED target with zero exported symbols
# (LNK1104). Revisit when ExtensionsAPI / ManagerAPI grow real exports.
add_library(APIs STATIC
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
