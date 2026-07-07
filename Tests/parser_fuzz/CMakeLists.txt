# Deterministic fuzz-lock across the new untrusted-input parsers. Compiles all
# four pure _logic TUs directly; links Qt6::Core alone.
add_executable(parser_fuzz_test
    parser_fuzz_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/nuclei_yaml_logic.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/inspector_logic.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/template_engine_logic.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/template_request_logic.cpp
)

target_link_libraries(parser_fuzz_test PRIVATE
    Qt6::Core
)

target_include_directories(parser_fuzz_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME parser_fuzz COMMAND parser_fuzz_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET parser_fuzz_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:parser_fuzz_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
