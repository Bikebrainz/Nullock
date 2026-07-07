# inspector_logic.cpp is pure (raw HTTP bytes -> structured JSON). Compile it
# DIRECTLY into the test so the binary links Qt6::Core alone.
add_executable(inspector_logic_test
    inspector_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/inspector_logic.cpp
)

target_link_libraries(inspector_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(inspector_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME inspector_logic COMMAND inspector_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET inspector_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:inspector_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
