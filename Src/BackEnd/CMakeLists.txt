# Add BackEnd submodules
add_subdirectory(Cache)
add_subdirectory(Proxy)
add_subdirectory(Control)

# Expose BackEnd targets to parent scope
set(BACKEND_LIBRARIES
    Cache
    Proxy
    Control
    PARENT_SCOPE
)
