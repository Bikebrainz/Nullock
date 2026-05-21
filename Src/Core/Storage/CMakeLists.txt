# Project persistence: per-project directory with project.json + an
# append-only history.ndjson stream. Deliberately not SQL — keeps the
# format human-inspectable and avoids a sqlite dependency.
add_library(Storage STATIC
    project_store.cpp
    project_store.hpp
)

target_link_libraries(Storage PUBLIC
    Qt6::Core
    Proxy
)

target_include_directories(Storage PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
