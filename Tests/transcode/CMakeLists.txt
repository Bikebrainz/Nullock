# transcode.cpp is the pure encode/decode/hash workbench (QString + QtCore crypto
# only -- no network). Compile it DIRECTLY into the test so the binary links
# Qt6::Core alone; this also recompiles transcode.cpp for the test.
add_executable(transcode_test
    transcode_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/transcode.cpp
)

target_link_libraries(transcode_test PRIVATE
    Qt6::Core
)

target_include_directories(transcode_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME transcode COMMAND transcode_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET transcode_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:transcode_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
