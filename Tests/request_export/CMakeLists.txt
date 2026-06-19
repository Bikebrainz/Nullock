add_executable(request_export_test
    request_export_test.cpp
)

target_link_libraries(request_export_test PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    Networking
    Proxy
    FrontEndGUI       # Networking's Repeater/Intruder pull ProxyModel symbols
)

target_include_directories(request_export_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME request_export COMMAND request_export_test)

# Windows: copy the config-appropriate Qt + project DLLs next to the exe.
if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    set(_qt_dlls
        Qt6Core${_d}.dll Qt6Network${_d}.dll Qt6Qml${_d}.dll Qt6Sql${_d}.dll
        Qt6Concurrent${_d}.dll
    )
    foreach(_dll IN LISTS _qt_dlls)
        add_custom_command(TARGET request_export_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_qt_bin}/${_dll}"
                "$<TARGET_FILE_DIR:request_export_test>/${_dll}"
            COMMAND_EXPAND_LISTS)
    endforeach()
    add_custom_command(TARGET request_export_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:FrontEndGUI>"
            "$<TARGET_FILE_DIR:request_export_test>/"
        COMMAND_EXPAND_LISTS)
endif()
