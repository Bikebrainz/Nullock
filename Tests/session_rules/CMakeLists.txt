add_executable(session_rules_test
    session_rules_test.cpp
)

# Exercises only the pure logic (globToRx, findCookieValue, jsonPathGet,
# substitute, firstCapture, the sanitizers, stripQuery) which lives in
# session_rules_logic.cpp and depends on Qt6::Core alone. Linking Networking
# pulls just that object -- NOT the SessionRules QObject (proxy_server.hpp) -- so
# the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(session_rules_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(session_rules_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME session_rules COMMAND session_rules_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET session_rules_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:session_rules_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
