# intercept_logic.cpp is the pure outgoing-byte resolver (QByteArray/QString only).
# Compile it DIRECTLY into the test so the binary links Qt6::Core alone (avoids the
# Proxy lib's QObject/QSemaphore intercept machinery + nghttp2). This also
# recompiles intercept_logic.cpp, so the test self-validates its compilation.
add_executable(intercept_logic_test
    intercept_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/intercept_logic.cpp
)

target_link_libraries(intercept_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(intercept_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME intercept_logic COMMAND intercept_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET intercept_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:intercept_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
