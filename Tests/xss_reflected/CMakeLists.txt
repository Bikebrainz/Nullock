add_executable(xss_reflected_test
    xss_reflected_test.cpp
)

# Exercises only the pure logic (inExecutingHtmlContext, isHtmlContentType,
# queryWith, buildRequest) which lives in xss_logic.cpp and depends on Qt6::Core
# alone. Linking Networking pulls just that object -- NOT xss_reflected.cpp's
# test() (HttpClient / Proxy::HttpResponse) -- so the binary stays free of the
# Network/Qml/GUI chain.
target_link_libraries(xss_reflected_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(xss_reflected_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME xss_reflected COMMAND xss_reflected_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET xss_reflected_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:xss_reflected_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
