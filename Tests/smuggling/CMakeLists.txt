add_executable(smuggling_test
    smuggling_test.cpp
)

# Exercises only the byte-exact probe builders (baselineRequest, clteProbe,
# teclProbe, ambiguousControl) which live in smuggling_logic.cpp and depend on
# Qt6::Core alone. Linking Networking pulls just that object -- NOT
# smuggling.cpp's test() (HttpClient timing) -- so the binary stays free of the
# Network/Qml/GUI chain.
target_link_libraries(smuggling_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(smuggling_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME smuggling COMMAND smuggling_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET smuggling_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:smuggling_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
