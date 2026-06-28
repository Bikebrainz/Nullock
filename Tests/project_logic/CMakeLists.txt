# project_logic.cpp is the pure project-name path-traversal guard (QString only).
# Compile it DIRECTLY into the test so the binary links Qt6::Core alone (avoids the
# Storage lib's project_store QObject). This also recompiles project_logic.cpp.
add_executable(project_logic_test
    project_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Storage/project_logic.cpp
)

target_link_libraries(project_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(project_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Storage
)

add_test(NAME project_logic COMMAND project_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET project_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:project_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
