add_executable(chain_runner_test
    chain_runner_test.cpp
)

# Exercises only the pure mutation helpers (sanitizeExtractedValue, jsonPathGet,
# substituteStr, normalizeContentLength, findHeader, findCookieValue) which live in
# chain_runner_logic.cpp and depend on Qt6::Core alone. Linking Networking pulls
# just that object -- NOT chain_runner.cpp's run() (HttpClient) -- so the binary
# stays free of the Network/Qml/GUI chain.
target_link_libraries(chain_runner_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(chain_runner_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME chain_runner COMMAND chain_runner_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET chain_runner_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:chain_runner_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
