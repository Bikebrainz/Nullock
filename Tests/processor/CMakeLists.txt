# processor.cpp is the pure payload-processing / filter-bypass variant generator
# (QString only -- no network). Compile it DIRECTLY into the test so the binary
# links Qt6::Core alone; this also recompiles processor.cpp for the test.
add_executable(processor_test
    processor_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/processor.cpp
)

target_link_libraries(processor_test PRIVATE
    Qt6::Core
)

target_include_directories(processor_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME processor COMMAND processor_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET processor_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:processor_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
