# content_decode.cpp uses <zlib.h> (Qt6Core's bundled zlib) but is otherwise a
# pure QByteArray helper. Compile it DIRECTLY into the test so the binary links
# Qt6::Core + Qt6::ZlibPrivate alone, avoiding the heavy Proxy link chain.
# Qt6::ZlibPrivate on Windows (bundled zlib); system zlib on Linux/macOS (Qt
# there builds against it and ships no private config).
find_package(Qt6 QUIET OPTIONAL_COMPONENTS ZlibPrivate)
if(TARGET Qt6::ZlibPrivate)
    set(_content_decode_zlib Qt6::ZlibPrivate)
else()
    find_package(ZLIB REQUIRED)
    set(_content_decode_zlib ZLIB::ZLIB)
endif()

add_executable(content_decode_test
    content_decode_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/content_decode.cpp
)

target_link_libraries(content_decode_test PRIVATE
    Qt6::Core
    ${_content_decode_zlib}
)

target_include_directories(content_decode_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME content_decode COMMAND content_decode_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET content_decode_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:content_decode_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
