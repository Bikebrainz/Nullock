add_executable(sequencer_test
    sequencer_test.cpp
)

# Sequencer::analyze is already pure (no network) and Qt6::Core-only, so no
# TU-split is needed -- the test just links Networking (for the Sequencer
# metaobject) + Qt6::Core and feeds crafted token corpora.
target_link_libraries(sequencer_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(sequencer_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME sequencer COMMAND sequencer_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET sequencer_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:sequencer_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
