# First test target of any kind for ProxyServer. It drives the real server over
# a loopback socket, so it links Proxy (and, transitively, whatever Proxy's own
# translation units call into) rather than compiling a pure _logic TU.
#
# It deliberately does NOT link Networking. proxy_server.cpp needs exactly four
# symbols from it -- SessionManager::injectInto, SessionRules::applyToRequest,
# TlsProfile::apply and HttpClient::defaultProfile -- but linking the library to
# get them drags Networking's SHARED mocs_compilation.o, which references every
# QObject in that lib including Intruder and Repeater, whose ProxyModel symbols
# resolve only in FrontEndGUI:
#     Networking.lib(intruder.obj) : LNK2019 ... ProxyModel::requestRawAt(int)
# (verified, not assumed -- the same wall that blocked #87). The three defining
# translation units are compiled DIRECTLY into the test instead, with the test's
# own AUTOMOC, which is the same escape hatch port_scan_live uses.
add_executable(proxy_shutdown_test
    proxy_shutdown_test.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/networking.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/networking_logic.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/networking_outcome.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/tls_profile.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/tls_profile_logic.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/session_manager.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/session_manager_logic.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/session_rules.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/session_rules_logic.cpp
    # session_rules.cpp's runMacro() replays a login sequence via
    # ChainRunner::run, so the à-la-carte link now needs the chain-runner TUs too
    # (they only pull HttpClient from networking.cpp, already listed above -- no
    # new QObject/moc, ChainRunner is a free-function namespace).
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/chain_runner.cpp
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking/chain_runner_logic.cpp
)

target_link_libraries(proxy_shutdown_test PRIVATE
    Qt6::Core
    Qt6::Network
    Proxy
    APIs
    # extensions_api.o (pulled in via Proxy -> ExtensionsApi::applyRequest/
    # applyResponse) calls CrashReporter::recordNonFatal() on a load/onUnload
    # error.
    Utils
)

target_include_directories(proxy_shutdown_test PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/BackEnd/Proxy
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)

add_test(NAME proxy_shutdown COMMAND proxy_shutdown_test)

if(WIN32)
    set(_qt_bin "${Qt6_DIR}/../../../bin")
    set(_d "$<$<CONFIG:Debug>:d>")
    foreach(_dll Qt6Core Qt6Network Qt6Qml Qt6Concurrent Qt6Sql)
        add_custom_command(TARGET proxy_shutdown_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_qt_bin}/${_dll}${_d}.dll"
                "$<TARGET_FILE_DIR:proxy_shutdown_test>/${_dll}${_d}.dll"
            COMMAND_EXPAND_LISTS)
    endforeach()
    # Proxy links nghttp2 (h2 upstream). Without the DLL beside the exe the
    # test dies at loader time with 0xC0000135 STATUS_DLL_NOT_FOUND before
    # main() ever runs -- which looks like a crash, not a missing dependency.
    if(NOT DEFINED NULLOCK_NGHTTP2_ROOT)
        set(NULLOCK_NGHTTP2_ROOT "D:/vcpkg/installed/x64-windows")
    endif()
    add_custom_command(TARGET proxy_shutdown_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${NULLOCK_NGHTTP2_ROOT}/bin/nghttp2.dll"
            "$<TARGET_FILE_DIR:proxy_shutdown_test>/nghttp2.dll"
        COMMAND_EXPAND_LISTS)
endif()
