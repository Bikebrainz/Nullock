add_executable(deser_probe_test
    deser_probe_test.cpp
)

# Exercises only the pure helpers (matchError signatures, the four builders'
# CR/LF guards, queryWith, the carrier name lists / ordering), which live in
# deser_logic.cpp and depend on Qt6::Core alone. Linking Networking pulls just
# that object -- NOT deser_probe.cpp's test() (HttpClient) -- so the binary
# stays free of the Network/Qml/GUI chain.
target_link_libraries(deser_probe_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(deser_probe_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME deser_probe COMMAND deser_probe_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET deser_probe_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:deser_probe_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
