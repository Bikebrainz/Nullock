add_executable(js_recon_test
    js_recon_test.cpp
)

# Exercises only the pure extraction (extractEndpoints, sourceMappingUrl) which
# lives in js_recon_logic.cpp and depends on Qt6::Core alone. Linking Networking
# pulls just that object -- NOT js_recon.cpp's scan() (HttpClient) -- so the
# binary stays free of the Network chain.
target_link_libraries(js_recon_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(js_recon_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME js_recon COMMAND js_recon_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET js_recon_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:js_recon_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
