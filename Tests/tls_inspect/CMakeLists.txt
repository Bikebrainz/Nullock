add_executable(tls_inspect_test
    tls_inspect_test.cpp
)

# Exercises only the pure evaluation logic (nameMatches, hostnameCovered,
# keyIsWeak, cipherWeakness, isOverbroadWildcard) which lives in tls_logic.cpp and
# depends on Qt6::Core alone. Linking Networking pulls just that object -- NOT
# tls_inspect.cpp's inspect() (QSslSocket/QSslCertificate) -- so the binary stays
# free of the Network/Qml/GUI chain.
target_link_libraries(tls_inspect_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(tls_inspect_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME tls_inspect COMMAND tls_inspect_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET tls_inspect_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:tls_inspect_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
