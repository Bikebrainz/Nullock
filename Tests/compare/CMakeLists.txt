# compare.cpp is the pure LCS word/line/char diff (QString + std::vector only --
# no network). Compile it DIRECTLY into the test so the binary links Qt6::Core
# alone; this also recompiles compare.cpp for the test.
add_executable(compare_test
    compare_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/compare.cpp
)

target_link_libraries(compare_test PRIVATE
    Qt6::Core
)

target_include_directories(compare_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME compare COMMAND compare_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET compare_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:compare_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
