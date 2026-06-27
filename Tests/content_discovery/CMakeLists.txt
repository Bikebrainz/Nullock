add_executable(content_discovery_test
    content_discovery_test.cpp
)

# Exercises only the pure logic (normBase, classify, forbiddenSaturated) which
# lives in content_logic.cpp and depends on Qt6::Core alone. Linking Networking
# pulls just that object -- NOT content_discovery.cpp's discover() (HttpClient) --
# so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(content_discovery_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(content_discovery_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME content_discovery COMMAND content_discovery_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET content_discovery_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:content_discovery_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
