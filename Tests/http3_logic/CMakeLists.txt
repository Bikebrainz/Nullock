# http3_logic.cpp is the pure HTTP/3-probe request builder + Alt-Svc parser
# (QByteArray/QString/QList only -- no HttpClient). Compile it DIRECTLY into the
# test so the binary links Qt6::Core alone. It pulls http3_detect.hpp for the
# Request/AltProtocol structs, which are plain Qt6::Core structs.
add_executable(http3_logic_test
    http3_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/http3_logic.cpp
)

target_link_libraries(http3_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(http3_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME http3_logic COMMAND http3_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET http3_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:http3_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
