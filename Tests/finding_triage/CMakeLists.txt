add_executable(finding_triage_test
    finding_triage_test.cpp
)

# Pure triage logic (identity key + suppression/false-positive predicates)
# depends on Qt6::Core alone. Linking Networking pulls just
# finding_triage_logic.o -- not the scanner QObject -- so the binary stays free
# of the Network/Qml chain.
target_link_libraries(finding_triage_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(finding_triage_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME finding_triage COMMAND finding_triage_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET finding_triage_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:finding_triage_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
