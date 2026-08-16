add_executable(scanner_regression_test
    scanner_regression_test.cpp
)

target_link_libraries(scanner_regression_test PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    Networking
    Proxy
    FrontEndGUI       # Networking's Repeater/Intruder pull ProxyModel symbols
    APIs              # session_rules.cpp's applyToRequestBytes() calls
                      # Proxy::serializeRequestForOrigin(), which pulls the whole
                      # proxy_server.o (incl. its ExtensionsApi::applyRequest/
                      # ResponseMutation calls) into this link; APIs supplies them.
                      # Safe here (unlike the historical LNK2019 risk noted in
                      # Src/Core/APIs/CMakeLists.txt): APIs no longer links
                      # Networking, and FrontEndGUI above already resolves any
                      # ProxyModel symbols Networking's Repeater/Intruder need.
)

target_include_directories(scanner_regression_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME scanner_regression COMMAND scanner_regression_test)

# Windows: copy the Qt + project DLLs we depend on next to the exe so it
# can run from the build directory without a fresh windeployqt. We rebuild
# this test every config and the DLLs change names per config, so a
# post-build hook is the simplest approach.
if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    set(_qt_dlls
        Qt6Core${_d}.dll Qt6Network${_d}.dll Qt6Qml${_d}.dll Qt6Sql${_d}.dll
        Qt6Concurrent${_d}.dll
    )
    foreach(_dll IN LISTS _qt_dlls)
        add_custom_command(TARGET scanner_regression_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_qt_bin}/${_dll}"
                "$<TARGET_FILE_DIR:scanner_regression_test>/${_dll}"
            COMMAND_EXPAND_LISTS)
    endforeach()
    # Sibling project DLLs (FrontEndGUI gives us ProxyModel symbols).
    add_custom_command(TARGET scanner_regression_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:FrontEndGUI>"
            "$<TARGET_FILE_DIR:scanner_regression_test>/"
        COMMAND_EXPAND_LISTS)
endif()
