# APIs is STATIC for now because the source files are stubs and MSVC will
# not emit an import .lib for a SHARED target with zero exported symbols
# (LNK1104). Revisit when ExtensionsAPI / ManagerAPI grow real exports.
add_library(APIs STATIC
    ExtensionsAPI/extensions_api.cpp
    ExtensionsAPI/extensions_api.hpp
    ExtensionsAPI/extension_perms_logic.cpp
    ExtensionsAPI/extension_perms_logic.hpp
    ManagerAPI/manager_api.cpp
    ManagerAPI/manager_api.hpp
    Oast/oast_server.cpp
    Oast/oast_server.hpp
    Oast/oast_logic.cpp
    Oast/oast_logic.hpp
    Oast/oast_correlator.cpp
    Oast/oast_correlator.hpp
    Oast/dns_sink.cpp
    Oast/dns_sink.hpp
    Oast/dns_logic.cpp
    Oast/dns_logic.hpp
)

# Qt6::Qml needed for QJSEngine which the ExtensionsAPI uses to execute
# user .js plugin files. Proxy is a public dep because extensions_api.hpp
# uses HttpRequest/HttpResponse in its public slot signature.
target_link_libraries(APIs PUBLIC
    Qt6::Core
    Qt6::Network
    Qt6::Qml
    Proxy
)

# APIs deliberately does NOT link Networking. It only ever needed one method --
# PassiveScanner::reportFinding, from ExtensionsApi and OastCorrelator -- and
# both now go through the header-only Core::IFindingSink (finding_sink.hpp),
# which PassiveScanner implements and app.cpp wires in at runtime.
#
# The link dependency was not free: it pulled Networking's SHARED
# mocs_compilation.o, which references every QObject in that lib including
# Intruder and Repeater, whose ProxyModel symbols resolve only in FrontEndGUI.
# Any test target linking APIs therefore died with
#   Networking.lib(intruder.obj) : LNK2019 ProxyModel::requestRawAt(int) const
# which is why the extension permission model had no tests at all. Keep it off.
# The include dir below stays -- headers are free; libraries are not.

# Include directories
target_include_directories(APIs PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/ExtensionsAPI
    ${CMAKE_CURRENT_SOURCE_DIR}/Oast
)
target_include_directories(APIs PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/Core/Networking
)
