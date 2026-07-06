cmake_minimum_required(VERSION 3.24)
project(Nullock
    VERSION 3.7.0
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
find_package(Qt6 REQUIRED COMPONENTS
    Core
    Gui
    Qml
    Quick
    QuickControls2
    Network
    Concurrent
    Sql
)

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
# just get a UAC / Gatekeeper warning the first time. See PACKAGING.md.

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
# On Linux/macOS the Qt runtime comes from the .deb/.rpm deps and the AppImage /
# .app bundling steps, not a sibling-dir copy -- and this $<CONFIG> path doesn't
# exist there.
if(WIN32)
    install(
        DIRECTORY ${CMAKE_BINARY_DIR}/Src/App/$<CONFIG>/
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime
        PATTERN "*.exe" EXCLUDE     # exe already installed via TARGETS rule
        PATTERN "*.pdb" EXCLUDE     # don't ship debug symbols
        PATTERN "*.lib" EXCLUDE
        PATTERN "*.exp" EXCLUDE
    )
endif()

# Linux: FrontEndGUI is a SHARED library NullockApp links. It must be installed
# next to the binary so linuxdeploy can find + bundle it into the AppImage
# (otherwise: "Could not find dependency: libFrontEndGUI.so"). Point the app's
# install RPATH at $ORIGIN so it resolves the .so from its own dir. Windows uses
# the POST_BUILD copy + windeployqt; macOS's .app + macdeployqt already handle it
# (its .dmg builds green) -- leave that path untouched.
if(UNIX AND NOT APPLE)
    install(TARGETS FrontEndGUI
        LIBRARY DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime
    )
    set_target_properties(NullockApp PROPERTIES INSTALL_RPATH "$ORIGIN")
endif()

# UI assets + extensions + labs.
install(
    DIRECTORY ui-v2/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/nullock/ui
    COMPONENT Runtime
    PATTERN "node_modules" EXCLUDE
)
install(
    DIRECTORY extensions/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/nullock/extensions
    COMPONENT Runtime
)
install(
    DIRECTORY browser-ext/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/nullock/browser-ext
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
        "libqt6core6, libqt6gui6, libqt6network6, libqt6qml6, libqt6quick6, libqt6sql6")
    set(CPACK_DEBIAN_PACKAGE_HOMEPAGE    "${PROJECT_HOMEPAGE_URL}")
    set(CPACK_RPM_PACKAGE_LICENSE        "MIT")
    set(CPACK_RPM_PACKAGE_GROUP          "Applications/Internet")
    set(CPACK_RPM_PACKAGE_URL            "${PROJECT_HOMEPAGE_URL}")
endif()

include(CPack)
