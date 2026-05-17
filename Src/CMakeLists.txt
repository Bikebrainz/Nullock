# Add Core module (contains static and shared libraries)
add_subdirectory(Core)

# Add BackEnd module (contains static libraries)
add_subdirectory(BackEnd)

# Add FrontEnd module (contains QML and models)
add_subdirectory(FrontEnd)

# Add main application executable
add_subdirectory(App)
