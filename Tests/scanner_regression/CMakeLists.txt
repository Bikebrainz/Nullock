add_executable(scanner_regression_test
    scanner_regression_test.cpp
)

target_link_libraries(scanner_regression_test PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    Networking
    Proxy
    FrontEndGUI       # Networking's Repeater/Intruder pull ProxyModel symbols
)

target_include_directories(scanner_regression_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
)

add_test(NAME scanner_regression COMMAND scanner_regression_test)
