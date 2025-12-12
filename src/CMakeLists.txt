# Compile sources into an object library
add_library(bbs_sources OBJECT
	bbs.c
	bbs_ciphersuites.c
	bbs_util.c
	sha256.c
	shake256.c
	compat-string.c
)
add_dependencies(bbs_sources blst)


# Main library
# We also link a special version for the fixture tests, which need access to
# some internal symbols to control the randomness. These are not exposed in the
# main library.
add_library(bbs               SHARED $<TARGET_OBJECTS:bbs_sources>)
add_library(bbs_FIXTURES_ONLY SHARED $<TARGET_OBJECTS:bbs_sources>)
target_link_libraries(bbs               PRIVATE ${SOURCE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}blst${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(bbs_FIXTURES_ONLY PRIVATE ${SOURCE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}blst${CMAKE_STATIC_LIBRARY_SUFFIX})
if(NOT APPLE)
	target_link_options(bbs PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/version.map)
endif()



