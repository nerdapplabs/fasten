cmake_minimum_required(VERSION 3.14)
project(fasten-cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# libfasten_core (Rust). Build it first:
#   cd ../fasten-core && cargo build --release --features all
# FASTEN_CORE_LIB_DIR defaults to ../fasten-core/target/release.
if(NOT FASTEN_CORE_LIB_DIR)
    set(FASTEN_CORE_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../fasten-core/target/release")
endif()

find_library(FASTEN_CORE_LIB
    NAMES fasten_core
    HINTS ${FASTEN_CORE_LIB_DIR}
    REQUIRED
)

add_library(fasten INTERFACE)
target_include_directories(fasten INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(fasten INTERFACE ${FASTEN_CORE_LIB})

# Warnings only; they are not treated as errors.
target_compile_options(fasten INTERFACE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

# Examples
option(FASTEN_BUILD_EXAMPLES "Build example binaries" ON)

if(FASTEN_BUILD_EXAMPLES)
    add_executable(connector examples/connector.cpp)
    target_link_libraries(connector PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(connector PRIVATE pthread)
    endif()

    # Uses fasten_reader.hpp only, no HTTP framework.
    add_executable(reader_example examples/reader_example.cpp)
    target_link_libraries(reader_example PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(reader_example PRIVATE pthread)
    endif()

    # Only with -DSIMPLE_WEB_SERVER_DIR=/path/to/Simple-Web-Server.
    if(SIMPLE_WEB_SERVER_DIR)
        add_executable(reader_simplehttp examples/reader_simplehttp_main.cpp)
        target_include_directories(reader_simplehttp PRIVATE ${SIMPLE_WEB_SERVER_DIR})
        target_link_libraries(reader_simplehttp PRIVATE fasten pthread)
    endif()
endif()

# Tests are off by default; CI passes -DFASTEN_BUILD_TESTS=ON.
option(FASTEN_BUILD_TESTS "Build smoke tests" OFF)

if(FASTEN_BUILD_TESTS)
    enable_testing()

    add_executable(pii_in_detail_smoke tests/pii_in_detail_smoke.cpp)
    target_link_libraries(pii_in_detail_smoke PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(pii_in_detail_smoke PRIVATE pthread)
    endif()
    add_test(NAME pii_in_detail_smoke COMMAND pii_in_detail_smoke)

    add_executable(redact_substring_smoke tests/redact_substring_smoke.cpp)
    target_link_libraries(redact_substring_smoke PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(redact_substring_smoke PRIVATE pthread)
    endif()
    add_test(NAME redact_substring_smoke COMMAND redact_substring_smoke)

    add_executable(redact_env_keys_smoke tests/redact_env_keys_smoke.cpp)
    target_link_libraries(redact_env_keys_smoke PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(redact_env_keys_smoke PRIVATE pthread)
    endif()
    add_test(NAME redact_env_keys_smoke COMMAND redact_env_keys_smoke)

    # Cases from spec/redact-conformance.json.
    add_executable(redact_conformance_smoke tests/redact_conformance_smoke.cpp)
    target_link_libraries(redact_conformance_smoke PRIVATE fasten)
    if(UNIX AND NOT APPLE)
        target_link_libraries(redact_conformance_smoke PRIVATE pthread)
    endif()
    add_test(NAME redact_conformance_smoke COMMAND redact_conformance_smoke)

    # Check the target, not SQLite3_FOUND: older CMake 3.x can set the latter
    # without creating SQLite3::SQLite3.
    find_package(SQLite3 QUIET)
    if(TARGET SQLite3::SQLite3)
        add_executable(sqlite_store_smoke tests/sqlite_store_smoke.cpp)
        target_link_libraries(sqlite_store_smoke PRIVATE fasten SQLite3::SQLite3)
        if(UNIX AND NOT APPLE)
            target_link_libraries(sqlite_store_smoke PRIVATE pthread)
        endif()
        add_test(NAME sqlite_store_smoke COMMAND sqlite_store_smoke)
    else()
        message(STATUS "SQLite3::SQLite3 target unavailable, skipping sqlite_store_smoke")
    endif()

    find_package(PostgreSQL QUIET)
    if(TARGET PostgreSQL::PostgreSQL)
        add_executable(postgres_store_smoke tests/postgres_store_smoke.cpp)
        target_link_libraries(postgres_store_smoke PRIVATE fasten PostgreSQL::PostgreSQL)
        if(UNIX AND NOT APPLE)
            target_link_libraries(postgres_store_smoke PRIVATE pthread)
        endif()
        add_test(NAME postgres_store_smoke COMMAND postgres_store_smoke)
    else()
        message(STATUS "PostgreSQL::PostgreSQL target unavailable, skipping postgres_store_smoke")
    endif()

    # Skipped without libyaml-cpp; CI installs libyaml-cpp-dev.
    find_library(YAMLCPP_LIB yaml-cpp)
    if(YAMLCPP_LIB)
        add_executable(codes_yaml_smoke tests/codes_yaml_smoke.cpp)
        target_link_libraries(codes_yaml_smoke PRIVATE fasten ${YAMLCPP_LIB})
        if(UNIX AND NOT APPLE)
            target_link_libraries(codes_yaml_smoke PRIVATE pthread)
        endif()
        add_test(NAME codes_yaml_smoke COMMAND codes_yaml_smoke)
    else()
        message(STATUS "yaml-cpp not found, skipping codes_yaml_smoke")
    endif()

    # Logger shims. spdlog and glog build against tests/shim_stubs/; the
    # Boost.Log test needs a real Boost.Log.

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
        message(STATUS "Boost.Log not found, skipping shim_boost_log_smoke")
    endif()
endif()

install(DIRECTORY include/ DESTINATION include)
