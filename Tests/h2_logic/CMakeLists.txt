# h2_logic.cpp is the pure HTTP/2 telemetry-bounding logic (QMap/QString only).
# Compile it DIRECTLY into the test so the binary links Qt6::Core alone. It pulls
# h2_events.hpp for the H2StreamSummary struct; the Q_OBJECT H2EventLog declared
# there is never instantiated by the test, so no MOC/link of it is needed (same
# pattern as intercept_logic). This also recompiles h2_logic.cpp.
add_executable(h2_logic_test
    h2_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/h2_logic.cpp
)

target_link_libraries(h2_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(h2_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME h2_logic COMMAND h2_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET h2_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:h2_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
