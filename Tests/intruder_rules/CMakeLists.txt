# intruder_rules.cpp is pure (QString in/out) and reuses transcode.cpp for the
# encode/hash ops. Compile both DIRECTLY into the test so the binary links
# Qt6::Core alone -- no Networking/Proxy chain. (Recompiles both here.)
add_executable(intruder_rules_test
    intruder_rules_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/intruder_rules.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/transcode.cpp
)

target_link_libraries(intruder_rules_test PRIVATE
    Qt6::Core
)

target_include_directories(intruder_rules_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME intruder_rules COMMAND intruder_rules_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET intruder_rules_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:intruder_rules_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
