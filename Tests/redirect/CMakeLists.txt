add_executable(redirect_test
    redirect_test.cpp
)

# Redirect cookies use Qt Network's URL-aware cookie jar.
target_link_libraries(redirect_test PRIVATE
    Qt6::Core
    Qt6::Network
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
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Network${_d}.dll"
            "$<TARGET_FILE_DIR:redirect_test>/Qt6Network${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
