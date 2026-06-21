add_executable(http_fingerprint_test
    http_fingerprint_test.cpp
)

# Exercises only the pure detect() table + buildGet's CR/LF guards, which live
# in http_fingerprint_logic.cpp and depend on Qt6::Core alone. Linking
# Networking pulls just that object -- NOT http_fingerprint.cpp's fingerprint()
# (HttpClient) -- so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(http_fingerprint_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(http_fingerprint_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME http_fingerprint COMMAND http_fingerprint_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET http_fingerprint_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:http_fingerprint_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
