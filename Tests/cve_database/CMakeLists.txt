add_executable(cve_database_test
    cve_database_test.cpp
)

target_link_libraries(cve_database_test PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    Networking
    Proxy
    FrontEndGUI       # Networking's Repeater/Intruder pull ProxyModel symbols
)

target_include_directories(cve_database_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME cve_database COMMAND cve_database_test)

# Windows: copy the Qt + project DLLs next to the exe so it runs from the
# build dir without a fresh windeployqt (mirrors scanner_regression).
if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_qt_dlls
        Qt6Cored.dll Qt6Networkd.dll Qt6Qmld.dll Qt6Sqld.dll
        Qt6Concurrentd.dll
    )
    foreach(_dll IN LISTS _qt_dlls)
        add_custom_command(TARGET cve_database_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_qt_bin}/${_dll}"
                "$<TARGET_FILE_DIR:cve_database_test>/${_dll}"
            COMMAND_EXPAND_LISTS)
    endforeach()
    add_custom_command(TARGET cve_database_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:FrontEndGUI>"
            "$<TARGET_FILE_DIR:cve_database_test>/"
        COMMAND_EXPAND_LISTS)
endif()
