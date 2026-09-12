cmake_minimum_required(VERSION 3.24)
project(Nullock
    VERSION 3.8.0
    DESCRIPTION "FOSS web security toolkit (proxy, repeater, intruder, scanner, OAST)"
    HOMEPAGE_URL "https://github.com/Bikebrainz/Nullock"
    LANGUAGES CXX
)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable automoc, autorcc, autouic for Qt
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6 with required components
find_package(Qt6 6.10.3 REQUIRED COMPONENTS
    Core
    Gui
    Qml
    Quick
    QuickControls2
    Network
    Concurrent
    Sql
)

if(WIN32)
    set(NULLOCK_NGHTTP2_ROOT "C:/vcpkg/installed/x64-windows" CACHE PATH "nghttp2 install prefix")
    set(NULLOCK_OPENSSL_ROOT "${NULLOCK_NGHTTP2_ROOT}" CACHE PATH "OpenSSL install prefix")
endif()

# Add source subdirectory
add_subdirectory(Src)

# Add Tests subdirectory (contains the code used to run tests)
enable_testing()
add_subdirectory(Tests)

# Fuzz harnesses (off by default; -DNULLOCK_FUZZ=ON to opt in).
# NOTE: capital-T "Tests" -- Linux's case-sensitive FS rejects "tests/fuzz".
add_subdirectory(Tests/fuzz)

# ---- Packaging / installers (CPack) -------------------------------------
#
# Builds platform-native installers:
#   Windows  : NSIS .exe installer (free; ships in vcpkg, also a free
#              standalone install)
#   Linux    : .deb (Debian/Ubuntu) + .rpm (Fedora/RHEL)
#   macOS    : .dmg (drag-to-Applications) -- requires building on a Mac
#   All OSes : .zip / .tar.gz raw artifact for power users
#
# Usage:
#   cmake --build build --config Release
#   cmake --build build --config Release --target package
# Output drops in build/_CPack_Packages/.
#
# No code signing here -- signed packaging is a wrapper that we kick off
# in CI once we have certs. The unsigned packages still install fine; users
# just get a UAC / Gatekeeper warning the first time. See packaging/README.md.

include(GNUInstallDirs)

# Install rules for the main exe + the Qt dependencies windeployqt copies
# next to it. We install everything from $<TARGET_FILE_DIR:NullockApp>
# because that directory already has the post-build deployment output
# (FrontEndGUI.dll, Qt6*.dll, sqldrivers/).
install(
    TARGETS NullockApp
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            COMPONENT Runtime
    BUNDLE  DESTINATION .            # macOS: NullockApp is a MACOSX_BUNDLE (.app)
            COMPONENT Runtime
)
# Windows only: windeployqt copies the Qt runtime DLLs + FrontEndGUI.dll +
# sqldrivers/ next to the exe as a post-build step, so we ship that whole dir.
# Linux/macOS use Qt's deployment script below instead of this Windows-only
# sibling-directory copy.
if(WIN32)
    install(
        DIRECTORY ${CMAKE_BINARY_DIR}/Src/App/$<CONFIG>/
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime
        PATTERN "NullockApp.exe" EXCLUDE # preserve the bundled OpenSSL executable
        PATTERN "*.pdb" EXCLUDE     # don't ship debug symbols
        PATTERN "*.lib" EXCLUDE
        PATTERN "*.exp" EXCLUDE
        # Install one current asset tree under share/nullock, not a second
        # development copy beside the executable.
        PATTERN "Src/App/*/ui-v2" EXCLUDE
        PATTERN "Src/App/*/templates" EXCLUDE
        PATTERN "Src/App/*/extensions" EXCLUDE
    )
endif()

# Install our own shared library before Qt deploys its dependencies. Qt's
# deployment tool cannot resolve an @rpath library absent from the staged app.
if(APPLE)
    install(TARGETS FrontEndGUI
        LIBRARY DESTINATION NullockApp.app/Contents/Frameworks COMPONENT Runtime)
    set_target_properties(NullockApp PROPERTIES
        INSTALL_RPATH "@executable_path/../Frameworks")
    set_target_properties(FrontEndGUI PROPERTIES INSTALL_RPATH "@loader_path")
elseif(UNIX)
    install(TARGETS FrontEndGUI
        LIBRARY DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime
    )
    set_target_properties(NullockApp FrontEndGUI PROPERTIES
        INSTALL_RPATH "$ORIGIN;$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
endif()

# Unix packages bundle the Qt version used to build, including QML and plugins.
# Relying on a distro's older Qt runtime does not satisfy Qt 6.10 symbols.
option(NULLOCK_DEPLOY_RUNTIME "Bundle Qt runtime dependencies when installing" ON)
if(UNIX AND NULLOCK_DEPLOY_RUNTIME)
    # History uses SQLite only. Qt's default SQL plugin set also includes
    # drivers for proprietary clients that are absent on a clean machine.
    set(_nullock_plugin_selection EXCLUDE_PLUGIN_TYPES sqldrivers INCLUDE_PLUGINS qsqlite qoffscreen)
    if(APPLE)
        # macdeployqt has no per-plugin filter. Install the native plugins used
        # by this app and pass each one back for framework/rpath deployment.
        set(_native_deploy_options -no-plugins)
        foreach(_plugin QCocoaIntegrationPlugin QOffscreenIntegrationPlugin
                QSQLiteDriverPlugin QTlsBackendOpenSSLPlugin
                QAppleNetworkInformationPlugin QJpegPlugin QGifPlugin QICOPlugin)
            get_target_property(_type Qt6::${_plugin} QT_PLUGIN_TYPE)
            set(_destination "NullockApp.app/Contents/PlugIns/${_type}")
            install(FILES "$<TARGET_FILE:Qt6::${_plugin}>"
                DESTINATION "${_destination}" COMPONENT Runtime)
            list(APPEND _native_deploy_options
                "-executable=${_destination}/$<TARGET_FILE_NAME:Qt6::${_plugin}>")
        endforeach()
        set(_nullock_plugin_selection DEPLOY_TOOL_OPTIONS ${_native_deploy_options})
    endif()
    qt_generate_deploy_qml_app_script(TARGET NullockApp OUTPUT_SCRIPT nullock_deploy
        NO_TRANSLATIONS ${_nullock_plugin_selection})
    install(SCRIPT ${nullock_deploy} COMPONENT Runtime)
    if(APPLE)
        # -no-plugins also suppresses macdeployqt's qt.conf generation.
        install(FILES packaging/macos/qt.conf
            DESTINATION NullockApp.app/Contents/Resources COMPONENT Runtime)
    endif()
endif()

set(NULLOCK_ASSET_DIR "${CMAKE_INSTALL_DATADIR}/nullock")
if(APPLE)
    # A dragged .app must contain its assets, independent of the DMG's folders.
    set(NULLOCK_ASSET_DIR "NullockApp.app/Contents/Resources/nullock")
endif()

# UI assets + extensions + labs.
install(
    DIRECTORY ui-v2/
    DESTINATION ${NULLOCK_ASSET_DIR}/ui
    COMPONENT Runtime
    PATTERN "node_modules" EXCLUDE
)
install(
    DIRECTORY extensions/
    DESTINATION ${NULLOCK_ASSET_DIR}/extensions
    COMPONENT Runtime
)
# Bundled detection templates + project templates -- read at runtime relative to
# the UI dir (uiDir/../templates), so they install next to nullock/ui.
install(
    DIRECTORY templates/
    DESTINATION ${NULLOCK_ASSET_DIR}/templates
    COMPONENT Runtime
)
install(
    DIRECTORY browser-ext/
    DESTINATION ${NULLOCK_ASSET_DIR}/browser-ext
    COMPONENT Optional
)
install(
    FILES bin/nullock
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                GROUP_EXECUTE GROUP_READ
                WORLD_EXECUTE WORLD_READ
    COMPONENT CLI
)
install(
    FILES LICENSE.md README.md SECURITY.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
    COMPONENT Runtime
)

# ---- CPack configuration ------------------------------------------------
set(CPACK_PACKAGE_NAME                "Nullock")
set(CPACK_PACKAGE_VENDOR              "Nullock Project")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VERSION             "${PROJECT_VERSION}")
set(CPACK_PACKAGE_HOMEPAGE_URL        "${PROJECT_HOMEPAGE_URL}")
set(CPACK_PACKAGE_CONTACT             "https://github.com/Bikebrainz/Nullock/issues")
set(CPACK_PACKAGE_INSTALL_DIRECTORY   "Nullock")
set(CPACK_RESOURCE_FILE_LICENSE       "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.md")
set(CPACK_RESOURCE_FILE_README        "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_STRIP_FILES                 TRUE)
set(CPACK_VERBATIM_VARIABLES          TRUE)

# Platform-specific generators. CPack picks the right one(s) by env.
if(WIN32)
    # NSIS gives us a graphical wizard, Start Menu shortcut, registry
    # uninstaller, optional desktop shortcut. ZIP is a fallback for
    # power users who don't want an installer.
    set(CPACK_GENERATOR                  "NSIS;ZIP")
    set(CPACK_NSIS_PACKAGE_NAME          "Nullock")
    set(CPACK_NSIS_DISPLAY_NAME          "Nullock")
    set(CPACK_NSIS_HELP_LINK             "${PROJECT_HOMEPAGE_URL}")
    set(CPACK_NSIS_URL_INFO_ABOUT        "${PROJECT_HOMEPAGE_URL}")
    set(CPACK_NSIS_CONTACT               "${CPACK_PACKAGE_CONTACT}")
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
    set(CPACK_NSIS_MODIFY_PATH           ON)
    set(CPACK_NSIS_CREATE_ICONS_EXTRA
        "CreateShortCut '$SMPROGRAMS\\\\Nullock\\\\Nullock.lnk' '$INSTDIR\\\\bin\\\\NullockApp.exe'")
    set(CPACK_NSIS_DELETE_ICONS_EXTRA
        "Delete '$SMPROGRAMS\\\\Nullock\\\\Nullock.lnk'")
elseif(APPLE)
    set(CPACK_GENERATOR                  "DragNDrop;TGZ")
    set(CPACK_DMG_VOLUME_NAME            "Nullock")
elseif(UNIX)
    # DEB + RPM + TGZ. Building DEB needs dpkg-deb on the host; RPM
    # needs rpmbuild. Both are present on most build hosts; if absent,
    # CPack drops only the formats it can build.
    set(CPACK_GENERATOR                  "DEB;RPM;TGZ")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER  "Nullock Project <noreply@github.com>")
    set(CPACK_DEBIAN_PACKAGE_SECTION     "net")
    set(CPACK_DEBIAN_PACKAGE_PRIORITY    "optional")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "openssl, libnghttp2-14, libxkbcommon0, libxcb-cursor0")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
    set(CPACK_RPM_PACKAGE_REQUIRES "openssl, libnghttp2, libxkbcommon, xcb-util-cursor")
    set(CPACK_DEBIAN_PACKAGE_HOMEPAGE    "${PROJECT_HOMEPAGE_URL}")
    set(CPACK_RPM_PACKAGE_LICENSE        "MIT")
    set(CPACK_RPM_PACKAGE_GROUP          "Applications/Internet")
    set(CPACK_RPM_PACKAGE_URL            "${PROJECT_HOMEPAGE_URL}")
endif()

include(CPack)
