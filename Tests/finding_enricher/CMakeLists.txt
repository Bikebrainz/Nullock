add_executable(finding_enricher_test
    finding_enricher_test.cpp
)

target_link_libraries(finding_enricher_test PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    Networking
    Proxy
    FrontEndGUI       # Networking's Repeater/Intruder pull ProxyModel symbols
)

target_include_directories(finding_enricher_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME finding_enricher COMMAND finding_enricher_test)

# Windows: copy the Qt + project DLLs next to the exe (mirrors scanner_regression).
if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_qt_dlls
        Qt6Cored.dll Qt6Networkd.dll Qt6Qmld.dll Qt6Sqld.dll
        Qt6Concurrentd.dll
    )
    foreach(_dll IN LISTS _qt_dlls)
        add_custom_command(TARGET finding_enricher_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_qt_bin}/${_dll}"
                "$<TARGET_FILE_DIR:finding_enricher_test>/${_dll}"
            COMMAND_EXPAND_LISTS)
    endforeach()
    add_custom_command(TARGET finding_enricher_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:FrontEndGUI>"
            "$<TARGET_FILE_DIR:finding_enricher_test>/"
        COMMAND_EXPAND_LISTS)
endif()
