find_library(GMP_LIB gmp REQUIRED)
find_path(GMP_PATH gmp.h REQUIRED)
message(STATUS "GMP_PATH: ${GMP_PATH}")

add_library(bbs SHARED
	bbs.c
	bbs_util.c)

set(BBS_CIPHER_SUITE "BLS12-381-SHA-256" CACHE STRING "BBS cipher suite")
set_property(CACHE BBS_CIPHER_SUITE PROPERTY STRINGS OPTION_DEFAULT "BLS12-381-SHA-256" "BLS12-381-SHAKE-256")

message(STATUS "BBS_CIPHER_SUITE selected: ${BBS_CIPHER_SUITE}")

if(BBS_CIPHER_SUITE STREQUAL "BLS12-381-SHA-256")
    target_compile_definitions(bbs PUBLIC BBS_CIPHER_SUITE=1)
elseif(BBS_CIPHER_SUITE STREQUAL "BLS12-381-SHAKE-256")
    target_compile_definitions(bbs PUBLIC BBS_CIPHER_SUITE=2)
else() # Default case
	message(WARNING "BBS_CIPHER_SUITE not recognized, defaulting to BLS12-381-SHA-256")
    target_compile_definitions(bbs PUBLIC BBS_CIPHER_SUITE=1)
endif()


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
