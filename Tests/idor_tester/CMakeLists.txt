add_executable(idor_tester_test
    idor_tester_test.cpp
)

# Exercises only the pure helpers (id recognition, neighbors/padding,
# withMutatedId, buildRequest CR/LF guards, controlUsable / isAccessible),
# which live in idor_logic.cpp and depend on Qt6::Core alone. Linking
# Networking pulls just that object -- NOT idor_tester.cpp's test() (HttpClient)
# -- so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(idor_tester_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(idor_tester_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME idor_tester COMMAND idor_tester_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET idor_tester_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:idor_tester_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
