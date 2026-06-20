add_executable(path_traversal_test
    path_traversal_test.cpp
)

# Exercises only the pure helpers (matchSig / buildRequest), which live in
# path_traversal_logic.cpp and depend on Qt6::Core alone. Linking Networking
# pulls just that object -- NOT path_traversal.cpp's test() (HttpClient) -- so the
# binary stays free of the Network/Qml/GUI chain.
target_link_libraries(path_traversal_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(path_traversal_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME path_traversal COMMAND path_traversal_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET path_traversal_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:path_traversal_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
