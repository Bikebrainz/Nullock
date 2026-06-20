add_executable(verb_tamper_test
    verb_tamper_test.cpp
)

# Exercises only the pure helpers (isDenied/isAllowed, buildRequest CR/LF
# guards, caseVariants, overrideAddedNothing, headIsBypass), which live in
# verb_tamper_logic.cpp and depend on Qt6::Core alone. Linking Networking pulls
# just that object -- NOT verb_tamper.cpp's test() (HttpClient) -- so the binary
# stays free of the Network/Qml/GUI chain.
target_link_libraries(verb_tamper_test PRIVATE
    Qt6::Core
    Networking
)

target_include_directories(verb_tamper_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME verb_tamper COMMAND verb_tamper_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")   # debug Qt DLLs carry a 'd' suffix; release don't
    add_custom_command(TARGET verb_tamper_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_qt_bin}/Qt6Core${_d}.dll"
            "$<TARGET_FILE_DIR:verb_tamper_test>/Qt6Core${_d}.dll"
        COMMAND_EXPAND_LISTS)
endif()
