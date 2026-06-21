add_executable(waf_detect_test
    waf_detect_test.cpp
)

# Exercises only the pure signature matcher (detectFromHeaders + sigs()) and
# buildGet's CR/LF guards, which live in waf_detect_logic.cpp and depend on
# Qt6::Core alone. Linking Networking pulls just those objects -- NOT
# waf_detect.cpp's detect() (HttpClient) -- so the binary stays free of the
# Network/Qml/GUI chain.
target_link_libraries(waf_detect_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(waf_detect_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME waf_detect COMMAND waf_detect_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET waf_detect_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:waf_detect_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
