add_executable(sequencer_capture_test
    sequencer_capture_test.cpp
)

# Exercises only the pure logic (extractToken / parseExtractFrom /
# clampCaptureCount) in sequencer_capture_logic.cpp, which depends on Qt6::Core
# alone (it reuses session_rules_logic's pure helpers). Linking Networking pulls
# just those objects -- NOT the SequencerCapture QObject (HttpClient/sockets) --
# so the binary stays free of the Network/Qml/GUI chain, same as session_rules.
target_link_libraries(sequencer_capture_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(sequencer_capture_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME sequencer_capture COMMAND sequencer_capture_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    add_custom_command(TARGET sequencer_capture_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:sequencer_capture_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
