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

    # reader_example needs no extra deps (uses fasten_reader.hpp core only).
    add_executable(reader_example examples/reader_example.cpp)
    target_link_libraries(reader_example PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(reader_example PRIVATE pthread)
    endif()

    # Simple-Web-Server adapter — only built when SIMPLE_WEB_SERVER_DIR is set.
    # cmake -DSIMPLE_WEB_SERVER_DIR=/path/to/Simple-Web-Server ..
    if(SIMPLE_WEB_SERVER_DIR)
        add_executable(reader_simplehttp examples/reader_simplehttp_main.cpp)
        target_include_directories(reader_simplehttp PRIVATE ${SIMPLE_WEB_SERVER_DIR})
        target_link_libraries(reader_simplehttp PRIVATE fasten pthread)
    endif()
endif()

# ── Tests ─────────────────────────────────────────────────────────────────
# Off by default — adopters embedding fasten don't need to build our tests.
# CI flips this on with -DFASTEN_BUILD_TESTS=ON.
option(FASTEN_BUILD_TESTS "Build smoke tests" OFF)

if(FASTEN_BUILD_TESTS)
    enable_testing()

    add_executable(pii_in_detail_smoke tests/pii_in_detail_smoke.cpp)
    target_link_libraries(pii_in_detail_smoke PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(pii_in_detail_smoke PRIVATE pthread)
    endif()
    add_test(NAME pii_in_detail_smoke COMMAND pii_in_detail_smoke)

    # P1-15: audit-store failure handling smoke
    add_executable(audit_queue_smoke tests/audit_queue_smoke.cpp)
    target_link_libraries(audit_queue_smoke PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(audit_queue_smoke PRIVATE pthread)
    endif()
    add_test(NAME audit_queue_smoke COMMAND audit_queue_smoke)

    # REVIEW.md item #1: substring-redact regression guard
    add_executable(redact_substring_smoke tests/redact_substring_smoke.cpp)
    target_link_libraries(redact_substring_smoke PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(redact_substring_smoke PRIVATE pthread)
    endif()
    add_test(NAME redact_substring_smoke COMMAND redact_substring_smoke)

    # sqlite_store_smoke needs sqlite3 at link time.
    # Guard with TARGET check: some cmake/platform combos set SQLite3_FOUND but
    # fail to create the SQLite3::SQLite3 IMPORTED target (cmake bug on older 3.x).
    find_package(SQLite3 QUIET)
    if(TARGET SQLite3::SQLite3)
        add_executable(sqlite_store_smoke tests/sqlite_store_smoke.cpp)
        target_link_libraries(sqlite_store_smoke PRIVATE fasten SQLite3::SQLite3)
        if(UNIX AND NOT APPLE)
            target_link_libraries(sqlite_store_smoke PRIVATE pthread)
        endif()
        add_test(NAME sqlite_store_smoke COMMAND sqlite_store_smoke)
    else()
        message(STATUS "SQLite3::SQLite3 target unavailable — skipping sqlite_store_smoke")
    endif()

    # postgres_store_smoke needs libpq at link time.
    find_package(PostgreSQL QUIET)
    if(TARGET PostgreSQL::PostgreSQL)
        add_executable(postgres_store_smoke tests/postgres_store_smoke.cpp)
        target_link_libraries(postgres_store_smoke PRIVATE fasten PostgreSQL::PostgreSQL)
        if(UNIX AND NOT APPLE)
            target_link_libraries(postgres_store_smoke PRIVATE pthread)
        endif()
        add_test(NAME postgres_store_smoke COMMAND postgres_store_smoke)
    else()
        message(STATUS "PostgreSQL::PostgreSQL target unavailable — skipping postgres_store_smoke")
    endif()

    # codes_yaml smoke needs libyaml-cpp at link time — guard so the build
    # doesn't fail on systems without it. CI installs libyaml-cpp-dev.
    find_library(YAMLCPP_LIB yaml-cpp)
    if(YAMLCPP_LIB)
        add_executable(codes_yaml_smoke tests/codes_yaml_smoke.cpp)
        target_link_libraries(codes_yaml_smoke PRIVATE fasten ${YAMLCPP_LIB})
        if(UNIX AND NOT APPLE)
            target_link_libraries(codes_yaml_smoke PRIVATE pthread)
        endif()
        add_test(NAME codes_yaml_smoke COMMAND codes_yaml_smoke)
    else()
        message(STATUS "yaml-cpp not found — skipping codes_yaml_smoke")
    endif()

    # P1-12: logger-shim smoke tests.
    # spdlog + glog use stub headers in tests/shim_stubs/ — no install required.
    # boost_log requires Boost.Log headers — guarded with find_package.

    add_executable(shim_spdlog_smoke tests/shim_spdlog_smoke.cpp)
    target_include_directories(shim_spdlog_smoke BEFORE PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/shim_stubs)
    target_link_libraries(shim_spdlog_smoke PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(shim_spdlog_smoke PRIVATE pthread)
    endif()
    add_test(NAME shim_spdlog_smoke COMMAND shim_spdlog_smoke)

    add_executable(shim_glog_smoke tests/shim_glog_smoke.cpp)
    target_include_directories(shim_glog_smoke BEFORE PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/shim_stubs)
    target_link_libraries(shim_glog_smoke PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(shim_glog_smoke PRIVATE pthread)
    endif()
    add_test(NAME shim_glog_smoke COMMAND shim_glog_smoke)

    find_package(Boost COMPONENTS log log_setup)
    if(Boost_LOG_FOUND)
        add_executable(shim_boost_log_smoke tests/shim_boost_log_smoke.cpp)
        target_link_libraries(shim_boost_log_smoke PRIVATE fasten
            Boost::log Boost::log_setup)
        if(UNIX AND NOT APPLE)
            target_link_libraries(shim_boost_log_smoke PRIVATE pthread)
        endif()
        add_test(NAME shim_boost_log_smoke COMMAND shim_boost_log_smoke)
    else()
        message(STATUS "Boost.Log not found — skipping shim_boost_log_smoke")
    endif()
endif()

# ── Install ───────────────────────────────────────────────────────────────
install(DIRECTORY include/ DESTINATION include)
