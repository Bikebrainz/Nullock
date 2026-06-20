add_executable(cors_tester_test
    cors_tester_test.cpp
)

# The test exercises only the pure helpers (registrableDomain / originSpecs /
# buildRequest), which live in cors_origin.cpp and depend on Qt6::Core alone.
# Linking Networking pulls just that object -- NOT cors_tester.cpp's test()
# (HttpClient) -- so the binary stays free of the Network/Qml/GUI DLL chain.
target_link_libraries(cors_tester_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(cors_tester_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME cors_tester COMMAND cors_tester_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET cors_tester_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:cors_tester_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
