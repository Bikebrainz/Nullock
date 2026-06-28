add_executable(networking_test
    networking_test.cpp
)

# Exercises only classifySocketOutcome (pure) which lives in
# networking_outcome.cpp and depends on Qt6::Network for the QAbstractSocket
# enum types alone. Linking Networking pulls just that object -- NOT
# HttpClient::send (the Proxy / socket I/O chain) -- so the binary stays light.
target_link_libraries(networking_test PRIVATE
    Qt6::Core
    Qt6::Network
    Networking
)

target_include_directories(networking_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME networking COMMAND networking_test)

# Pure response-parser cores (status line / headers / Content-Length / chunked
# decoder). networking_logic.cpp is QByteArray/QString-only, so we compile it
# DIRECTLY into the test and link Qt6::Core ALONE -- no Qt6::Network, no socket,
# no event loop -- which also proves the TU stays free of the heavy deps.
add_executable(networking_logic_test
    networking_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/networking_logic.cpp
)
target_link_libraries(networking_logic_test PRIVATE Qt6::Core)
target_include_directories(networking_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)
add_test(NAME networking_logic COMMAND networking_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET networking_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:networking_test>/Qt6Core${_d}.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Network${_d}.dll"
            "$<TARGET_FILE_DIR:networking_test>/Qt6Network${_d}.dll"
        COMMAND_EXPAND_LISTS)
    add_custom_command(TARGET networking_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:networking_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
