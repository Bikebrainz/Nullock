# payload_forge.cpp is a pure PoC-payload generator (QByteArray/QString only --
# no network, no clock, no randomness). Compile it DIRECTLY into the test so the
# binary links Qt6::Core alone, and the test recompiles payload_forge.cpp itself.
add_executable(payload_forge_test
    payload_forge_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/payload_forge.cpp
)

target_link_libraries(payload_forge_test PRIVATE
    Qt6::Core
)

target_include_directories(payload_forge_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME payload_forge COMMAND payload_forge_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET payload_forge_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:payload_forge_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
