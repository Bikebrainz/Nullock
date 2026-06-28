# history_logic.cpp is the pure find() query builder (QJsonObject/QVariant/QString
# only -- no QSqlDatabase). Compile it DIRECTLY into the test so the binary links
# Qt6::Core alone (history_index.cpp itself pulls Qt6::Sql). This also recompiles
# history_logic.cpp, so the test self-validates its compilation.
add_executable(history_logic_test
    history_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Storage/history_logic.cpp
)

target_link_libraries(history_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(history_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Storage
)

add_test(NAME history_logic COMMAND history_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET history_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:history_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
