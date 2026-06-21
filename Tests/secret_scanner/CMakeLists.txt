add_executable(secret_scanner_test
    secret_scanner_test.cpp
)

# Exercises only the pure helpers (scanText, acceptSecret, looksPlaceholder,
# mask, sameOriginScripts, buildGet CR/LF guards), which live in
# secret_logic.cpp and depend on Qt6::Core alone. Linking Networking pulls just
# that object -- NOT secret_scanner.cpp's scan() (HttpClient) -- so the binary
# stays free of the Network/Qml/GUI chain.
target_link_libraries(secret_scanner_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(secret_scanner_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME secret_scanner COMMAND secret_scanner_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET secret_scanner_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:secret_scanner_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
