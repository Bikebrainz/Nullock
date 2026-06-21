add_executable(param_miner_test
    param_miner_test.cpp
)

# Exercises only the pure helpers (canaryFor, buildRequest CR/LF + dup-header
# guards, canaryReflected, statusFlipConfirmed), which live in param_logic.cpp
# and depend on Qt6::Core alone. Linking Networking pulls just that object --
# NOT param_miner.cpp's mine() (HttpClient) -- so the binary stays free of the
# Network/Qml/GUI chain.
target_link_libraries(param_miner_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(param_miner_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME param_miner COMMAND param_miner_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET param_miner_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:param_miner_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
