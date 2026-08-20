# extensions_utils_logic.cpp is the pure codec/hash module behind nullock.utils.*
# (QByteArray/QString/QCryptographicHash only -- no QObject, no engine). Compile it
# DIRECTLY into the test so the binary links Qt6::Core alone and self-validates its
# compilation.
add_executable(extensions_utils_logic_test
    extensions_utils_logic_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/ExtensionsAPI/extensions_utils_logic.cpp
)

target_link_libraries(extensions_utils_logic_test PRIVATE
    Qt6::Core
)

target_include_directories(extensions_utils_logic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/APIs/ExtensionsAPI
)

add_test(NAME extensions_utils_logic COMMAND extensions_utils_logic_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET extensions_utils_logic_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:extensions_utils_logic_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
