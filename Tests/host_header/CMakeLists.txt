add_executable(host_header_test
    host_header_test.cpp
)

# Exercises only the pure helpers (locationIsUrl / bodyHasUrl / buildRequest),
# which live in host_header_logic.cpp and depend on Qt6::Core alone. Linking
# Networking pulls just that object -- NOT host_header.cpp's test() (HttpClient)
# -- so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(host_header_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(host_header_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME host_header COMMAND host_header_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET host_header_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:host_header_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
