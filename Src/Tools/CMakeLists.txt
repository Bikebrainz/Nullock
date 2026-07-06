# Standalone headless tools.

# nullock-oast: the deployable OAST callback sink. It reuses OastServer directly
# (compiled in, not via the APIs lib) so the binary stays lean -- Qt Core +
# Network only, no Qml/Proxy/Networking/GUI baggage. See DEPLOY_OAST.md.
qt_add_executable(nullock-oast
    oast_server_main.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast/oast_server.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast/oast_server.hpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast/oast_logic.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast/oast_logic.hpp
)

target_include_directories(nullock-oast PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast
)

target_link_libraries(nullock-oast PRIVATE
    Qt6::Core
    Qt6::Network
)

# nullock-workspace: the deployable team-workspace sync server (findings push/
# pull over SQLite + a shared bearer key). Self-contained -- Qt Core + Network +
# Sql only. See design/team-workspaces.md and DEPLOY_WORKSPACE.md.
qt_add_executable(nullock-workspace
    workspace_server_main.cpp
)

target_link_libraries(nullock-workspace PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Sql
)
