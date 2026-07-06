# intruder_persist_logic.cpp is pure (structs <-> JSON). The Rule / ExtractSpec
# structs it uses are header-only, so compile it DIRECTLY into the test and link
# Qt6::Core alone.
add_executable(intruder_persist_logic_test
    intruder_persist_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/intruder_persist_logic.cpp
)

target_link_libraries(intruder_persist_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(intruder_persist_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME intruder_persist_logic COMMAND intruder_persist_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET intruder_persist_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:intruder_persist_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
