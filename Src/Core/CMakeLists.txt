# Add Core submodules
add_subdirectory(APIs)
add_subdirectory(Storage)
add_subdirectory(Networking)
add_subdirectory(Utils)

# Expose Core targets to parent scope
set(CORE_LIBRARIES
    APIs
    Storage
    Networking
    Utils
    PARENT_SCOPE
)
