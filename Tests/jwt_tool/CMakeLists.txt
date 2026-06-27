add_executable(jwt_tool_test
    jwt_tool_test.cpp
)

# jwt_tool is pure (QCryptographicHash/QJsonDocument/QMessageAuthenticationCode --
# Qt6::Core only). Linking Networking pulls just jwt_tool.o, no Network chain.
target_link_libraries(jwt_tool_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(jwt_tool_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME jwt_tool COMMAND jwt_tool_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET jwt_tool_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:jwt_tool_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
