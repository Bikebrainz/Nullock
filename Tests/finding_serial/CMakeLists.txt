# Findings-persistence wire format: FindingSerial::toJson/fromJson round-trip.
# Compiles finding_serial.cpp directly; links the same set as finding_enricher
# (the Finding struct pulls proxy_server.hpp / passive_scanner.hpp). No I/O.
# Run via:  ctest -R finding_serial -V
add_executable(finding_serial_test
    finding_serial_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Storage/finding_serial.cpp
)

target_link_libraries(finding_serial_test PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    Networking
    Proxy
    FrontEndGUI       # Networking's Repeater/Intruder pull ProxyModel symbols
)

target_include_directories(finding_serial_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
    ${CMAKE_SOURCE_DIR}/Src/Core/Storage
)

add_test(NAME finding_serial COMMAND finding_serial_test)

# Windows: copy the Qt + project DLLs next to the exe (mirrors finding_enricher).
if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    set(_qt_dlls
        Qt6Core${_d}.dll Qt6Network${_d}.dll Qt6Qml${_d}.dll Qt6Sql${_d}.dll
        Qt6Concurrent${_d}.dll
    )
    foreach(_dll IN LISTS _qt_dlls)
        add_custom_command(TARGET finding_serial_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_qt_bin}/${_dll}"
                "$<TARGET_FILE_DIR:finding_serial_test>/${_dll}"
            COMMAND_EXPAND_LISTS)
    endforeach()
    add_custom_command(TARGET finding_serial_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:FrontEndGUI>"
            "$<TARGET_FILE_DIR:finding_serial_test>/"
        COMMAND_EXPAND_LISTS)
endif()
