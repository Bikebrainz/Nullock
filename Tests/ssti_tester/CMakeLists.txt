add_executable(ssti_tester_test
    ssti_tester_test.cpp
)

# Exercises only the pure helpers (confirmsArithmetic / renderedRegions /
# stripGroupingDigits / buildRequest), which live in ssti_logic.cpp and depend
# on Qt6::Core alone. Linking Networking pulls just that object -- NOT
# ssti_tester.cpp's test() (HttpClient) -- so the binary stays free of the
# Network/Qml/GUI DLL chain.
target_link_libraries(ssti_tester_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(ssti_tester_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME ssti_tester COMMAND ssti_tester_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET ssti_tester_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:ssti_tester_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
