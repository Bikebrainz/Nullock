# Create static library for Networking
add_library(Networking STATIC
    networking.cpp
    networking.hpp
    repeater.cpp
    repeater.hpp
    intruder.cpp
    intruder.hpp
    passive_scanner.cpp
    passive_scanner.hpp
    port_scanner.cpp
    port_scanner.hpp
    recon_engine.cpp
    recon_engine.hpp
    session_manager.cpp
    session_manager.hpp
    session_rules.cpp
    session_rules.hpp
    crawler.cpp
    crawler.hpp
    tls_profile.cpp
    tls_profile.hpp
    update_check.cpp
    update_check.hpp
    sequencer.cpp
    sequencer.hpp
    finding_enricher.cpp
    finding_enricher.hpp
    cve_database.cpp
    cve_database.hpp
    chain_runner.cpp
    chain_runner.hpp
    jwt_tool.cpp
    jwt_tool.hpp
    param_miner.cpp
    param_miner.hpp
    idor_tester.cpp
    idor_tester.hpp
    mass_assign.cpp
    mass_assign.hpp
    cors_tester.cpp
    cors_tester.hpp
    js_recon.cpp
    js_recon.hpp
    race_tester.cpp
    race_tester.hpp
)

# Networking exposes Repeater which references ProxyModel and the
# HttpRequest/HttpResponse types from Proxy. Both need to be PUBLIC
# because they appear in our public headers.
target_link_libraries(Networking PUBLIC
    Qt6::Core
    Qt6::Network
    Qt6::Concurrent
    Proxy
)

# Repeater includes "Proxy/proxy_model.hpp" which lives in FrontEndGUI's
# tree, but we only need the header at compile time -- the symbols resolve
# when App links both Networking and FrontEndGUI at the final link step.
# Linking the QML module DLL here caused STATUS_ENTRYPOINT_NOT_FOUND on
# Windows; just inherit the include path directly.
target_include_directories(Networking PRIVATE
    ${CMAKE_SOURCE_DIR}/Src/FrontEnd/GUI
    ${CMAKE_SOURCE_DIR}/Src/FrontEnd/GUI/Models
)

# Include directories
target_include_directories(Networking PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
