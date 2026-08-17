add_executable(redirect_test
    redirect_test.cpp
)

# Pure redirect logic (status/URL-resolution/method/policy/cookies/request-build)
# depends on Qt6::Core alone. Linking Networking pulls just redirect_logic.o --
# not the Repeater QObject -- so the binary stays free of the Network/Qml chain.
target_link_libraries(redirect_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(redirect_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME redirect COMMAND redirect_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET redirect_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:redirect_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
