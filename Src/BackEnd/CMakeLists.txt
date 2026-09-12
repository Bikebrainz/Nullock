# Add BackEnd submodules
add_subdirectory(Proxy)
add_subdirectory(Control)

# Expose BackEnd targets to parent scope
set(BACKEND_LIBRARIES
    Proxy
    Control
    PARENT_SCOPE
)
