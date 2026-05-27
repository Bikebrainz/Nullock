# APIs is STATIC for now because the source files are stubs and MSVC will
# not emit an import .lib for a SHARED target with zero exported symbols
# (LNK1104). Revisit when ExtensionsAPI / ManagerAPI grow real exports.
add_library(APIs STATIC
    ExtensionsAPI/extensions_api.cpp
    ExtensionsAPI/extensions_api.hpp
    ManagerAPI/manager_api.cpp
    ManagerAPI/manager_api.hpp
)

# Qt6::Qml needed for QJSEngine which the ExtensionsAPI uses to execute
# user .js plugin files. Proxy is a public dep because extensions_api.hpp
# uses HttpRequest/HttpResponse in its public slot signature.
target_link_libraries(APIs PUBLIC
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    Proxy
)

# Include directories
target_include_directories(APIs PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/ExtensionsAPI
)
