# Define QML module with sources
qt_add_qml_module(FrontEndGUI
    URI Nullock.FrontEnd
    VERSION 1.0
    PLUGIN_TARGET FrontEndGUIPlugin
    CLASS_NAME FrontEndGUIPlugin
    SOURCES
    Models/DevicesHub/devices_hub_model.cpp
    Models/DevicesHub/devices_hub_model.hpp
    Models/ExtensionsHub/extensions_hub_model.cpp
    Models/ExtensionsHub/extensions_hub_model.hpp
    Models/IntruderHub/intruder_hub_model.cpp
    Models/IntruderHub/intruder_hub_model.hpp
    Models/Overview/overview_model.cpp
    Models/Overview/overview_model.hpp
    Models/Proxy/proxy_model.cpp
    Models/Proxy/proxy_model.hpp
    Models/RepeaterHub/repeater_hub_model.cpp
    Models/RepeaterHub/repeater_hub_model.hpp
    Models/Workspace/workspace_model.cpp
    Models/Workspace/workspace_model.hpp
    Themes/themes_manager.cpp
    Themes/themes_manager.hpp
    QML_FILES
    DevicesHub/devices_hub.qml
    DevicesHub/Components/devices_console.qml
    DevicesHub/Components/devices.qml
    ExtensionsHub/extensions_hub.qml
    ExtensionsHub/Components/extensions_console.qml
    ExtensionsHub/Components/extensions.qml
    IntruderHub/intruder_hub.qml
    IntruderHub/Components/intruder_console.qml
    IntruderHub/Components/intruder.qml
    Overview/overview.qml
    Overview/Components/scope.qml
    Overview/Components/sitemap.qml
    Proxy/proxy.qml
    Proxy/Components/http_history.qml
    Proxy/Components/intercept.qml
    RepeaterHub/repeater_hub.qml
    RepeaterHub/Components/repeater_console.qml
    RepeaterHub/Components/repeater.qml
    Workspace/workspace.qml
    Workspace/Components/notes.qml
    Workspace/Components/report_generator.qml
    Workspace/Components/settings.qml
    Workspace/Components/themes.qml
)

# Link Qt libraries and backend modules whose headers the models include
target_link_libraries(FrontEndGUI PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Proxy
)

# Include directories
target_include_directories(FrontEndGUI PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Models
    ${CMAKE_CURRENT_SOURCE_DIR}/Themes
)

