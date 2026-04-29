cmake_minimum_required(VERSION 3.14)
project(fasten-cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Interface library — header-only, zero link deps ───────────────────────
add_library(fasten INTERFACE)
target_include_directories(fasten INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Warn on common pitfalls; treat warnings as errors in CI.
target_compile_options(fasten INTERFACE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

# ── Example ───────────────────────────────────────────────────────────────
option(FASTEN_BUILD_EXAMPLES "Build example binaries" ON)

if(FASTEN_BUILD_EXAMPLES)
    add_executable(connector examples/connector.cpp)
    target_link_libraries(connector PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(connector PRIVATE pthread)
    endif()
endif()

# ── Install ───────────────────────────────────────────────────────────────
install(DIRECTORY include/ DESTINATION include)
