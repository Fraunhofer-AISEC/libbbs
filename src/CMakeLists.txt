find_library(GMP_LIB gmp REQUIRED)
find_path(GMP_PATH gmp.h REQUIRED)
message(STATUS "GMP_PATH: ${GMP_PATH}")

add_library(bbs SHARED
	bbs.c
	bbs_util.c)


# set_property(TARGET bbs PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(bbs PUBLIC ../include)
target_include_directories(bbs PUBLIC ${SOURCE_DIR}/include)
target_include_directories(bbs PUBLIC ${SOURCE_DIR}/src/md)
target_include_directories(bbs PUBLIC ${SOURCE_DIR}/src/tmpl)
target_include_directories(bbs PUBLIC ${BINARY_DIR}/include)
target_include_directories(bbs PUBLIC ${GMP_PATH})

add_dependencies(bbs relic)
target_link_libraries(bbs PUBLIC ${GMP_LIB})
target_link_libraries(bbs PRIVATE
    ${BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}relic_s${CMAKE_STATIC_LIBRARY_SUFFIX})

include(GNUInstallDirs)
install(TARGETS bbs LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
