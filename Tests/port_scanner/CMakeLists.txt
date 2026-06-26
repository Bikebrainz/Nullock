add_executable(port_scanner_test
    port_scanner_test.cpp
)

# Exercises only classifyBanner (pure) which lives in port_logic.cpp and depends
# on Qt6::Core alone. Linking Networking pulls just that object -- NOT the
# PortScanner QObject (threads/sockets, and its moc) -- so the binary stays free
# of the Network/Qml/GUI chain.
target_link_libraries(port_scanner_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(port_scanner_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME port_scanner COMMAND port_scanner_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET port_scanner_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:port_scanner_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
