add_executable(crawler_test
    crawler_test.cpp
)

# Exercises only the pure logic (truncateBodyAtTag, resolveBase, extractRawLinks,
# canonicalLink, inDefaultScope) which lives in crawler_logic.cpp and depends on
# Qt6::Core alone. Linking Networking pulls just that object -- NOT the Crawler
# QObject (QObject/QtConcurrent/proxy_server) -- so the binary stays free of the
# Network/Qml/GUI chain.
target_link_libraries(crawler_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(crawler_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME crawler COMMAND crawler_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET crawler_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:crawler_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
