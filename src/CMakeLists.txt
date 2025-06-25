if(RELIC_ARITH STREQUAL "gmp")
	find_library(GMP_LIB gmp REQUIRED)
	find_path(GMP_PATH gmp.h REQUIRED)
	message(STATUS "GMP_PATH: ${GMP_PATH}")
endif()

# Compile sources into an object library
add_library(bbs_sources OBJECT
	bbs.c
	bbs_ciphersuites.c
	bbs_util.c
	sha256.c
	shake256.c
)
target_include_directories(bbs_sources PUBLIC .)
target_include_directories(bbs_sources PUBLIC ../include)
target_include_directories(bbs_sources PUBLIC ${BINARY_DIR}/include)
target_include_directories(bbs_sources PUBLIC ${GMP_PATH})


# Main library
# set_property(TARGET bbs PROPERTY POSITION_INDEPENDENT_CODE ON)
add_library(bbs SHARED $<TARGET_OBJECTS:bbs_sources>)
target_link_options(bbs PUBLIC -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/version.map)
target_link_libraries(bbs PUBLIC ${GMP_LIB})
target_link_libraries(bbs PRIVATE ${BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}relic_s${CMAKE_STATIC_LIBRARY_SUFFIX})
add_dependencies(bbs relic)

# Build a second version just for fixture tests, which has more symbols available
add_library(bbs_FIXTURES_ONLY SHARED $<TARGET_OBJECTS:bbs_sources>)
target_link_libraries(bbs_FIXTURES_ONLY PUBLIC ${GMP_LIB})
target_link_libraries(bbs_FIXTURES_ONLY PRIVATE ${BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}relic_s${CMAKE_STATIC_LIBRARY_SUFFIX})
add_dependencies(bbs_FIXTURES_ONLY relic)


include(GNUInstallDirs)
install(TARGETS bbs LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
