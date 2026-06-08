# Fuzz harnesses for the byte-eating parsers. Off by default -- enable
# with -DNULLOCK_FUZZ=ON. The clang-cl + libFuzzer path produces real
# fuzz binaries; the MSVC path produces standalone drivers that you
# feed a file/dir and they replay every byte through the parser
# (useful in CI to replay a corpus without dragging in clang).

option(NULLOCK_FUZZ "Build the parser fuzz harnesses" OFF)
if(NOT NULLOCK_FUZZ)
    return()
endif()

set(IS_CLANG_CL FALSE)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND MSVC)
    set(IS_CLANG_CL TRUE)
endif()

function(add_nullock_fuzzer name source link_libs)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE ${link_libs})
    if(IS_CLANG_CL)
        target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address)
        target_link_options(${name}    PRIVATE -fsanitize=fuzzer,address)
    else()
        # MSVC / GCC fallback: build the standalone driver instead.
        target_compile_definitions(${name} PRIVATE NULLOCK_FUZZ_STANDALONE=1)
    endif()
endfunction()

add_nullock_fuzzer(fuzz_ws_parser
                   fuzz_ws_parser.cpp
                   "Proxy")
add_nullock_fuzzer(fuzz_har_import
                   fuzz_har_import.cpp
                   "Storage;Qt6::Core")

# Seed corpora to bootstrap libFuzzer.
add_custom_target(fuzz_corpora ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/corpus/ws
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/corpus/har)
