# Project persistence: per-project directory with project.json + an
# append-only history.ndjson stream. Deliberately not SQL — keeps the
# format human-inspectable and avoids a sqlite dependency.
add_library(Storage STATIC
    project_store.cpp
    project_store.hpp
    project_logic.cpp
    project_logic.hpp
    history_index.cpp
    history_index.hpp
)

target_link_libraries(Storage PUBLIC
    Qt6::Core
    Qt6::Sql
    Proxy
)

target_include_directories(Storage PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
