add_executable(nosql_injection_test
    nosql_injection_test.cpp
)

# Exercises only the pure helpers (confirmsInjection / lenDiffers / buildRequest),
# which live in nosql_logic.cpp and depend on Qt6::Core alone. Linking Networking
# pulls just that object -- NOT nosql_injection.cpp's test() (HttpClient) -- so the
# binary stays free of the Network/Qml/GUI chain.
target_link_libraries(nosql_injection_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(nosql_injection_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME nosql_injection COMMAND nosql_injection_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET nosql_injection_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:nosql_injection_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
