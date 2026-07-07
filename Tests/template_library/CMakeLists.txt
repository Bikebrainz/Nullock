# Validates the bundled detection templates (templates/detections/*.json) by
# parsing each through the real template engine. TEMPLATES_DIR points the test
# at the source-tree library. Compiles template_engine_logic.cpp; Qt6::Core.
add_executable(template_library_test
    template_library_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/template_engine_logic.cpp
)

target_link_libraries(template_library_test PRIVATE
    Qt6::Core
)

target_include_directories(template_library_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

target_compile_definitions(template_library_test PRIVATE
    TEMPLATES_DIR="${CMAKE_SOURCE_DIR}/templates/detections"
)

add_test(NAME template_library COMMAND template_library_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET template_library_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:template_library_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
