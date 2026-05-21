# Add Core submodules
add_subdirectory(AppController)
add_subdirectory(APIs)
add_subdirectory(Storage)
add_subdirectory(Networking)
add_subdirectory(Nullem)
add_subdirectory(Utils)

# Expose Core targets to parent scope
set(CORE_LIBRARIES
    AppController
    APIs
    Storage
    Networking
    Nullem
    Utils
    PARENT_SCOPE
)
