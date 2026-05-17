# Create main executable with QML files
qt_add_executable(NullockApp
    app.cpp
    app.qml
)

# Register the QML module for the App
qt_add_qml_module(NullockApp
    URI Nullock.App
    VERSION 1.0
    QML_FILES app.qml
)

# Link all Core modules (both static and shared)
target_link_libraries(NullockApp PRIVATE
    AppController
    APIs
    Database
    Networking
    Nullem
    Utils
)

# Link all BackEnd modules (static)
target_link_libraries(NullockApp PRIVATE
    Cache
    Proxy
)

# Link FrontEnd QML module
target_link_libraries(NullockApp PRIVATE
    FrontEndGUI
    FrontEndResources
)

# Link Qt libraries
target_link_libraries(NullockApp PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
)

# Set executable properties based on platform
if(APPLE)
    set_target_properties(NullockApp PROPERTIES
        MACOSX_BUNDLE ON
    )
elseif(WIN32)
    set_target_properties(NullockApp PROPERTIES
        WIN32_EXECUTABLE ON
    )
endif()
