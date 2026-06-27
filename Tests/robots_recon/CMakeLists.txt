add_executable(robots_recon_test
    robots_recon_test.cpp
)

# Exercises only the pure parsing (looksLikeRobots, parseRobots, parseSitemapLocs,
# isSitemapIndex) which lives in robots_logic.cpp and depends on Qt6::Core alone.
# Linking Networking pulls just that object -- NOT robots_recon.cpp's scan()
# (HttpClient) -- so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(robots_recon_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(robots_recon_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME robots_recon COMMAND robots_recon_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET robots_recon_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:robots_recon_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
