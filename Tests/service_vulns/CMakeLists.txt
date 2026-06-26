add_executable(service_vulns_test
    service_vulns_test.cpp
)

# Exercises only the pure version matcher (parseBanner, matchVersion, the
# overlay) which lives in service_vulns_logic.cpp and depends on Qt6::Core
# alone. Linking Networking pulls just that object -- NOT service_vulns.cpp's
# grabBanner()/scan() (QTcpSocket) -- so the binary stays free of the
# Network/Qml/GUI chain.
target_link_libraries(service_vulns_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(service_vulns_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME service_vulns COMMAND service_vulns_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET service_vulns_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:service_vulns_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
