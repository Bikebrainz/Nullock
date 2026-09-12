# Native models and themes; the application window is in Src/App/app.qml.
qt_add_qml_module(FrontEndGUI
    URI Nullock.FrontEnd
    VERSION 1.0
    PLUGIN_TARGET FrontEndGUIPlugin
    CLASS_NAME FrontEndGUIPlugin
    SOURCES
    frontend_gui_export.hpp
    Models/Proxy/proxy_model.cpp
    Models/Proxy/proxy_model.hpp
    Models/Proxy/proxy_filter_model.cpp
    Models/Proxy/proxy_filter_model.hpp
    Models/Proxy/site_map_model.cpp
    Models/Proxy/site_map_model.hpp
    Themes/themes_manager.cpp
    Themes/themes_manager.hpp
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
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Models
    ${CMAKE_CURRENT_SOURCE_DIR}/Themes
)

# Mark classes that the App needs to link against (e.g. ProxyModel used
# via setContextProperty) with FRONTEND_GUI_EXPORT in their headers. This
# define switches that macro to Q_DECL_EXPORT while we build the DLL.
target_compile_definitions(FrontEndGUI PRIVATE FRONTEND_GUI_LIBRARY)

