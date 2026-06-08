cmake_minimum_required(VERSION 3.24)
project(Nullock LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable automoc, autorcc, autouic for Qt
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6 with required components
find_package(Qt6 REQUIRED COMPONENTS
    Core
    Gui
    Qml
    Quick
    QuickControls2
    Network
    Concurrent
    Sql
)

# Add source subdirectory
add_subdirectory(Src)

# Add Tests subdirectory (contains the code used to run tests)
enable_testing()
add_subdirectory(Tests)

# Fuzz harnesses (off by default; -DNULLOCK_FUZZ=ON to opt in).
add_subdirectory(tests/fuzz)
