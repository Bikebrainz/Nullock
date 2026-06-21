add_executable(takeover_scan_test
    takeover_scan_test.cpp
)

# Exercises only the pure helpers (the fingerprint matcher and buildGet's CR/LF
# guards), which live in takeover_logic.cpp and depend on Qt6::Core alone.
# Linking Networking pulls just that object -- NOT takeover_scan.cpp's scan()
# (HttpClient) -- so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(takeover_scan_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(takeover_scan_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME takeover_scan COMMAND takeover_scan_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET takeover_scan_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:takeover_scan_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
