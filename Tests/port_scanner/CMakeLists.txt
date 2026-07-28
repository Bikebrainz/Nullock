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

# LIVE scanner test: drives PortScanner::run() against a loopback listener so the
# probe-thread join (unconditional t->wait() + qDeleteAll) is actually executed --
# the pure test above cannot reach it.
#
# port_scanner.cpp is compiled DIRECTLY here instead of linking Networking. That
# lib's AUTOMOC emits ONE shared mocs_compilation.o covering every QObject in it,
# so referencing the PortScanner QObject drags in Repeater too, whose ProxyModel
# symbols only resolve when App also links FrontEndGUI. port_scanner.cpp includes
# nothing but Qt headers, so compiling it in keeps this target on
# Qt6::Core/Network/Concurrent with its own AUTOMOC -- the same
# compile-the-TU-directly pattern Tests/networking uses for networking_logic.
add_executable(port_scan_live_test
    port_scan_live_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/port_scanner.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/port_logic.cpp
)
set_target_properties(port_scan_live_test PROPERTIES AUTOMOC ON)
target_link_libraries(port_scan_live_test PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Concurrent
)
target_include_directories(port_scan_live_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)
add_test(NAME port_scan_live COMMAND port_scan_live_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET port_scanner_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:port_scanner_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
    add_custom_command(TARGET port_scan_live_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:port_scan_live_test>/Qt6Core${_d}.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Network${_d}.dll"
            "$<TARGET_FILE_DIR:port_scan_live_test>/Qt6Network${_d}.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Concurrent${_d}.dll"
            "$<TARGET_FILE_DIR:port_scan_live_test>/Qt6Concurrent${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
