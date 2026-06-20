add_executable(mass_assign_test
    mass_assign_test.cpp
)

# Exercises only the pure helpers (looksJson, acceptedStatus, buildRequest
# CR/LF guards), which live in mass_assign_logic.cpp and depend on Qt6::Core
# alone. Linking Networking pulls just that object -- NOT mass_assign.cpp's
# test() (HttpClient) -- so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(mass_assign_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(mass_assign_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME mass_assign COMMAND mass_assign_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET mass_assign_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:mass_assign_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
