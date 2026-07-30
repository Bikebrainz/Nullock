# Exercises only the pure marketplace logic (catalog parsing, the https/host
# allow-list, sha256 integrity, filename confinement, the install audit and the
# installed/available merge), which lives in marketplace_logic.cpp and depends on
# Qt6::Core alone. Linking Networking pulls just that object -- NOT
# marketplace.cpp's HttpClient/QFile side -- so the binary stays free of the
# Network/Qml/GUI chain, the same arrangement update_check_test uses.
add_executable(marketplace_logic_test
    marketplace_logic_test.cpp
)

target_link_libraries(marketplace_logic_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(marketplace_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME marketplace_logic COMMAND marketplace_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    foreach(_dll Qt6Core Qt6Network)
        add_custom_command(TARGET marketplace_logic_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_qt_bin}/${_dll}${_d}.dll"
                "$<TARGET_FILE_DIR:marketplace_logic_test>/${_dll}${_d}.dll"
            COMMAND_EXPAND_LISTS)
    endforeach()
endif()
