cmake_minimum_required(VERSION 3.5)

project(git-mirrorer C)

if ("${VERSION}" STREQUAL "")
    execute_process(
        COMMAND bash scripts/version.sh
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE VERSION
        ERROR_QUIET)
    message("-- Version generated: ${VERSION}")
else()
    message("-- Version defined: ${VERSION}")
endif()

add_executable(git-mirrorer
    git-mirrorer.c)

target_link_libraries(git-mirrorer
    git2
    yaml)

target_compile_definitions(git-mirrorer PRIVATE
    VERSION="${VERSION}")