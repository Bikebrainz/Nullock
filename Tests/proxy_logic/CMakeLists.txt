# proxy_logic.cpp is pure HTTP/1.1 framing logic (QByteArray/QList only -- no
# QtNetwork) but lives in the heavy Proxy lib (nghttp2/Qml/Network). Compile it
# DIRECTLY into the test so the binary links Qt6::Core alone, avoiding the proxy
# link chain. (This also means the test itself recompiles proxy_logic.cpp.)
add_executable(proxy_logic_test
    proxy_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/proxy_logic.cpp
)

target_link_libraries(proxy_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(proxy_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME proxy_logic COMMAND proxy_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET proxy_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:proxy_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
