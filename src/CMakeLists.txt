# Compile sources into an object library
add_library(bbs_sources OBJECT
	bbs.c
	bbs_ciphersuites.c
	bbs_util.c
	sha256.c
	shake256.c
	compat-string.c
)
target_include_directories(bbs_sources PUBLIC .)
target_include_directories(bbs_sources PUBLIC ../include)
target_include_directories(bbs_sources PUBLIC ${SOURCE_DIR}/bindings)


# Main library
# set_property(TARGET bbs PROPERTY POSITION_INDEPENDENT_CODE ON)
add_library(bbs SHARED $<TARGET_OBJECTS:bbs_sources>)
if(NOT APPLE)
target_link_options(bbs PUBLIC -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/version.map)
endif()
target_link_libraries(bbs PRIVATE
	${SOURCE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}blst${CMAKE_STATIC_LIBRARY_SUFFIX})
add_dependencies(bbs blst)

# Build a second version just for fixture tests, which has more symbols available
add_library(bbs_FIXTURES_ONLY SHARED $<TARGET_OBJECTS:bbs_sources>)
target_link_libraries(bbs_FIXTURES_ONLY PRIVATE
	${SOURCE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}blst${CMAKE_STATIC_LIBRARY_SUFFIX})
add_dependencies(bbs_FIXTURES_ONLY blst)


include(GNUInstallDirs)
install(TARGETS bbs LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
