add_executable(method_audit_test
    method_audit_test.cpp
)

# Exercises only the pure helpers (buildReq, parseAllow, dangerousWriteMethods,
# dangerousWebdavMethods, traceEchoed) which live in method_audit_logic.cpp and
# depend on Qt6::Core alone. Linking Networking pulls just that object -- NOT
# method_audit.cpp's audit() (HttpClient / Proxy::HttpResponse) -- so the binary
# stays free of the Network/Qml/GUI chain.
target_link_libraries(method_audit_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(method_audit_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME method_audit COMMAND method_audit_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET method_audit_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:method_audit_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
