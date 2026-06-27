add_executable(recon_engine_test
    recon_engine_test.cpp
)

# Exercises only the pure logic (cleanName, acceptCertName, recordMatchesQuery,
# isWildcardResolved) which lives in recon_logic.cpp and depends on Qt6::Core
# alone. Linking Networking pulls just that object -- NOT the ReconEngine QObject
# (QDnsLookup/QtConcurrent) -- so the binary stays free of the Network chain.
target_link_libraries(recon_engine_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(recon_engine_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME recon_engine COMMAND recon_engine_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET recon_engine_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:recon_engine_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
