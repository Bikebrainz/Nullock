# scope_logic.cpp is the pure advanced-scope decision logic (QString/QRegularExpression
# /QJson only). Compile it DIRECTLY into the test so the binary links Qt6::Core
# alone (avoids the Proxy lib's QObject/nghttp2 machinery), and self-validates its
# compilation.
add_executable(scope_logic_test
    scope_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/scope_logic.cpp
)

target_link_libraries(scope_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(scope_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME scope_logic COMMAND scope_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET scope_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:scope_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
