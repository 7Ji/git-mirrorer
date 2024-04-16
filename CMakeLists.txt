add_executable(git-mirrorer
    git-mirrorer.c)

target_link_libraries(git-mirrorer
    git2
    yaml)