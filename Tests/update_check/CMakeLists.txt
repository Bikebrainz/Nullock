add_executable(update_check_test
    update_check_test.cpp
)

# Exercises only the pure logic (compareSemver, isTrustedReleaseUrl) which lives in
# update_check_logic.cpp and depends on Qt6::Core alone. Linking Networking pulls
# just that object -- NOT update_check.cpp's doCheck() (HttpClient/QtConcurrent) --
# so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(update_check_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(update_check_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME update_check COMMAND update_check_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET update_check_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:update_check_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
