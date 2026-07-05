# h2_server_logic.cpp is the pure server-side h2 translation (QByteArray/QString
# only). It depends on h2_client_logic.cpp (HeaderNV + isHopByHopHeader). Compile
# BOTH directly into the test so the binary links Qt6::Core alone.
add_executable(h2_server_logic_test
    h2_server_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/h2_server_logic.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/h2_client_logic.cpp
)

target_link_libraries(h2_server_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(h2_server_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME h2_server_logic COMMAND h2_server_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET h2_server_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:h2_server_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
