# oast_logic.cpp is the pure OAST-token extractor (QString + QRegularExpression,
# no QtNetwork). Compile it DIRECTLY into the test so the binary links Qt6::Core
# alone, avoiding the APIs/QtNetwork chain. (This also recompiles oast_logic.cpp.)
add_executable(oast_logic_test
    oast_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast/oast_logic.cpp
)

target_link_libraries(oast_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(oast_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/Oast
)

add_test(NAME oast_logic COMMAND oast_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET oast_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:oast_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
