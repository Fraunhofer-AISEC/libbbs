add_executable(bbs bbs_cli_key_generation.c main.c)
find_library(ARGP_LIBRARY argp)
target_link_libraries(bbs PRIVATE bbs-dev)
target_link_libraries(bbs PRIVATE ${ARGP_LIBRARY})
target_include_directories(bbs PRIVATE ${ARGP_INCLUDE_DIR})

include(GNUInstallDirs)
install(TARGETS bbs RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
