# Standalone headless tools.

# nullock-oast: the deployable OAST callback sink. It reuses OastServer directly
# (compiled in, not via the APIs lib) so the binary stays lean -- Qt Core +
# Network only, no Qml/Proxy/Networking/GUI baggage. See DEPLOY_OAST.md.
qt_add_executable(nullock-oast
    oast_server_main.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast/oast_server.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast/oast_server.hpp
)

target_include_directories(nullock-oast PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast
)

target_link_libraries(nullock-oast PRIVATE
    Qt6::Core
    Qt6::Network
)
