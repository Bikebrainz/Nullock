# Add BackEnd submodules
add_subdirectory(Cache)
add_subdirectory(Proxy)

# Expose BackEnd targets to parent scope
set(BACKEND_LIBRARIES
    Cache
    Proxy
    PARENT_SCOPE
)
