add_executable(race_tester_test
    race_tester_test.cpp
)

# Exercises only the pure helpers (classify / isSafeMethod and buildRequest's
# CR/LF guards), which live in race_logic.cpp and depend on Qt6::Core alone.
# Linking Networking pulls just that object -- NOT race_tester.cpp's test()
# (HttpClient / QtConcurrent) -- so the binary stays free of the network chain.
target_link_libraries(race_tester_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(race_tester_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME race_tester COMMAND race_tester_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET race_tester_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:race_tester_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
