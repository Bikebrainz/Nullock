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

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET extension_perms_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:extension_perms_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
