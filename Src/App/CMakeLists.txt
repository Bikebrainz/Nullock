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
    Storage
    Networking
    Nullem
    Utils
)

# Link all BackEnd modules (static)
target_link_libraries(NullockApp PRIVATE
    Cache
    Proxy
    Control
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
    Qt6::QuickControls2
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

    # FrontEndGUI is a SHARED lib on Windows. The Qt-exported export macro
    # lives in its dll, so it has to sit next to NullockApp.exe at runtime.
    # Without this, post-rebuild runs blow up with STATUS_ENTRYPOINT_NOT_FOUND
    # because windeployqt won't pull our own DLLs across.
    add_custom_command(TARGET NullockApp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:FrontEndGUI>
            $<TARGET_FILE_DIR:NullockApp>
        COMMENT "copying FrontEndGUI.dll next to NullockApp.exe"
    )

    # Qt6Concurrent isn't directly referenced by anything in NullockApp.cpp,
    # so windeployqt scans the import table and misses it -- even though
    # Networking and Control both pull QtConcurrent::run via static libs.
    # Manually deploy it.
    add_custom_command(TARGET NullockApp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:Qt6::Concurrent>
            $<TARGET_FILE_DIR:NullockApp>
        COMMENT "deploying Qt6Concurrent.dll"
    )

    # Need Qt::Concurrent linked into NullockApp so the post-build copy
    # has a Qt6::Concurrent target to reference.
    target_link_libraries(NullockApp PRIVATE Qt6::Concurrent)

    # Qt6Sql.dll same story: only reached transitively via Storage's
    # use of QSqlDatabase. Without this manual copy, NullockApp.exe
    # fails to load at startup with a DLL-not-found error.
    target_link_libraries(NullockApp PRIVATE Qt6::Sql)
    add_custom_command(TARGET NullockApp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:Qt6::Sql>
            $<TARGET_FILE_DIR:NullockApp>
        COMMENT "deploying Qt6Sql.dll"
    )

    # Plus the SQLite driver plugin. QSqlDatabase loads sqldrivers/qsqlite.dll
    # at runtime; if it's absent the addDatabase("QSQLITE") call returns
    # an invalid handle and HistoryIndex silently degrades. We derive the
    # plugin path from Qt6::Core's location (typically <prefix>/bin) by
    # walking up one level and into plugins/sqldrivers.
    get_target_property(_qtcore_loc Qt6::Core LOCATION)
    get_filename_component(_qt_bin_dir "${_qtcore_loc}" DIRECTORY)
    get_filename_component(_qt_prefix  "${_qt_bin_dir}" DIRECTORY)
    add_custom_command(TARGET NullockApp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:NullockApp>/sqldrivers"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_prefix}/plugins/sqldrivers/qsqlite.dll"
            "$<TARGET_FILE_DIR:NullockApp>/sqldrivers/"
        COMMENT "deploying qsqlite driver plugin"
    )
endif()
