# extension_perms_logic.cpp is pure (JS source / caps in, decision out).
# Compile it DIRECTLY into the test so the binary links Qt6::Core alone.
add_executable(extension_perms_logic_test
    extension_perms_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/ExtensionsAPI/extension_perms_logic.cpp
)

target_link_libraries(extension_perms_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(extension_perms_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/ExtensionsAPI
)

add_test(NAME extension_perms_logic COMMAND extension_perms_logic_test)

# The pure test above proves the permission DECISION is right. It cannot see
# whether that decision is ENFORCED -- the bypass it missed was JS
# object-reference semantics, which needs a real QJSEngine. This drives the
# actual ExtensionsApi against real extension files in a QStandardPaths sandbox.
#
# This target only became possible once APIs stopped LINKING Networking (it now
# depends on the header-only Core::IFindingSink instead). Before that, linking
# APIs pulled Networking's shared mocs_compilation.o -> Intruder/Repeater ->
# ProxyModel -> FrontEndGUI and died with LNK2019.
add_executable(extensions_api_grant_test
    extensions_api_grant_test.cpp
)
target_link_libraries(extensions_api_grant_test PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    APIs
    Utils
)
target_include_directories(extensions_api_grant_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/ExtensionsAPI
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
    ${CMAKE_SOURCE_DIR}/Src/Core/Utils
)
add_test(NAME extensions_api_grant COMMAND extensions_api_grant_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET extension_perms_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:extension_perms_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
    foreach(_dll Qt6Core Qt6Network Qt6Qml)
        add_custom_command(TARGET extensions_api_grant_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_qt_bin}/${_dll}${_d}.dll"
                "$<TARGET_FILE_DIR:extensions_api_grant_test>/${_dll}${_d}.dll"
            COMMAND_EXPAND_LISTS)
    endforeach()
endif()
