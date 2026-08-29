# Tiny HTTP control server. Hosts the React UI from ui-v2/ and exposes a
# read+write JSON API the UI consumes instead of the old mock-data.js.
add_library(Control STATIC
    control_server.cpp
    control_server.hpp
    control_logic.cpp
    control_logic.hpp
)

target_link_libraries(Control PUBLIC
    Qt6::Core
    Qt6::Network
    Qt6::Sql
    Proxy
)
# Bake in the build version so the marketplace compatibility gate ([B31]) can
# compare a catalog entry's minVersion against the running build.
target_compile_definitions(Control PRIVATE
    NULLOCK_VERSION="${PROJECT_VERSION}"
)
# extensions_api.hpp (included transitively for ExtensionsApi forward decl)
# pulls in <QJSEngine>; only used in the .cpp's snapshot builder, so keep
# Qml as a PRIVATE compile-time dep.
target_link_libraries(Control PRIVATE Qt6::Qml Qt6::Gui)

# Control consumes ProxyModel, SiteMapModel, ProxyFilterModel, ProjectStore,
# Repeater, Intruder, InterceptController, CertAuthority, ThemesManager,
# ExtensionsApi. We only need their headers at compile time -- the App link
# step resolves the symbols.
target_include_directories(Control PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/FrontEnd/GUI
    ${CMAKE_SOURCE_DIR}/Src/FrontEnd/GUI/Models
    ${CMAKE_SOURCE_DIR}/Src/FrontEnd/GUI/Themes
    ${CMAKE_SOURCE_DIR}/Src/Core/Storage
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/ExtensionsAPI
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast
    ${CMAKE_SOURCE_DIR}/Src/Core/Utils
)

target_include_directories(Control PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
