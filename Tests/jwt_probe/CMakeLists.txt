add_executable(jwt_probe_test
    jwt_probe_test.cpp
)

# Exercises only the pure forgery/request builders (buildRequest,
# corruptSignature, algNoneVariants, ...) which live in jwt_probe_logic.cpp and
# the pure jwt_tool.cpp -- both depend on Qt6::Core alone. Linking Networking
# pulls just those objects, NOT jwt_probe.cpp's testOneCarrier() (HttpClient),
# so the binary stays free of the Network/Qml/GUI chain.
target_link_libraries(jwt_probe_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(jwt_probe_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME jwt_probe COMMAND jwt_probe_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET jwt_probe_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:jwt_probe_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
