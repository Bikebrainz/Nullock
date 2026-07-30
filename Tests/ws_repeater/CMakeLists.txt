# ws_repeater.cpp lives in the heavy Proxy lib but reaches nothing from it: its
# only dependencies are Qt containers, QRandomGenerator, and QTcpSocket (needed
# solely because QPointer<QTcpSocket> wants a complete type -- no socket call is
# ever made). So compile the TU directly rather than linking Proxy, the same
# escape used by websocket_test. It carries Q_OBJECT, hence AUTOMOC.
set(CMAKE_AUTOMOC ON)

add_executable(ws_repeater_test
    ws_repeater_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy/ws_repeater.cpp
)

# Core + Network only. Qt6::Test would have been the obvious home for QSignalSpy,
# but `Test` is not one of the components the top-level find_package(Qt6) asks
# for, so naming it here risks a configure-time failure that takes the whole
# build with it. The test records the signal by hand instead. Network is needed
# only because QPointer<QTcpSocket> wants the complete type.
target_link_libraries(ws_repeater_test PRIVATE
    Qt6::Core
    Qt6::Network
)

target_include_directories(ws_repeater_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME ws_repeater COMMAND ws_repeater_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    foreach(_dll Qt6Core Qt6Network)
        add_custom_command(TARGET ws_repeater_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_qt_bin}/${_dll}${_d}.dll"
                "$<TARGET_FILE_DIR:ws_repeater_test>/${_dll}${_d}.dll"
            COMMAND_EXPAND_LISTS)
    endforeach()
endif()
