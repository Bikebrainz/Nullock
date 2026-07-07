# nuclei_yaml_logic.cpp is pure (YAML string -> template JSON). Compile it +
# template_engine_logic.cpp (for the round-trip) directly into the test; both
# link Qt6::Core alone.
add_executable(nuclei_yaml_logic_test
    nuclei_yaml_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/nuclei_yaml_logic.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/template_engine_logic.cpp
)

target_link_libraries(nuclei_yaml_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(nuclei_yaml_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME nuclei_yaml_logic COMMAND nuclei_yaml_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET nuclei_yaml_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:nuclei_yaml_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
