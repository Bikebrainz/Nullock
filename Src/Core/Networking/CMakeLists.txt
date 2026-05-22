# Create static library for Networking
add_library(Networking STATIC
    networking.cpp
    networking.hpp
    repeater.cpp
    repeater.hpp
)

# Networking exposes Repeater which references ProxyModel and the
# HttpRequest/HttpResponse types from Proxy. Both need to be PUBLIC
# because they appear in our public headers.
target_link_libraries(Networking PUBLIC
    Qt6::Core
    Qt6::Network
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
