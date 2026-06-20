add_executable(cache_deception_test
    cache_deception_test.cpp
)

# Exercises only the pure helpers (randTok / lenSimilar / isCatchAll /
# buildGet), which live in cache_deception_logic.cpp and depend on Qt6::Core
# alone. Linking Networking pulls just that object -- NOT cache_deception.cpp's
# test() (HttpClient) -- so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(cache_deception_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(cache_deception_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME cache_deception COMMAND cache_deception_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET cache_deception_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:cache_deception_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
