# Create resource library
qt_add_resources(FrontEndResources
    resources.qrc
)

# Add resource target as library
add_library(FrontEndResources STATIC ${FrontEndResources})

# Link Qt libraries
target_link_libraries(FrontEndResources PRIVATE
    Qt6::Core
)
