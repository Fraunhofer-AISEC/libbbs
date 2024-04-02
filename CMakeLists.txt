cmake_minimum_required(VERSION 3.10)

project(
  libbbs
  VERSION 0.1
  LANGUAGES C)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CheckCCompilerFlag OPTIONAL)
include(CTest)

install(DIRECTORY "${CMAKE_SOURCE_DIR}/${CMAKE_INSTALL_INCLUDEDIR}"
        DESTINATION ${CMAKE_INSTALL_PREFIX})

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_FULL_LIBDIR}")
set(CMAKE_BUILD_WITH_RPATH TRUE)

set(RELIC_CFLAGS
    "-O3 -fomit-frame-pointer -fPIC"
    CACHE INTERNAL "")

check_c_compiler_flag("-finline-small-functions" INLINE_SMALL_FUNCS_SUPPORTED)
if(INLINE_SMALL_FUNCS_SUPPORTED)
  set(RELIC_CFLAGS
      "${RELIC_CFLAGS} -finline-small-functions"
      CACHE INTERNAL "")
else()
  message(STATUS "-finline-small-functions not supported.")
endif()


message(STATUS "Relic CFLAGS: ${RELIC_CFLAGS}")
include(ExternalProject)
ExternalProject_Add(
  relic
  GIT_REPOSITORY https://github.com/relic-toolkit/relic.git
  GIT_TAG 6f7e8e3c73132f606ea72fbd176d8ce9e4cb2bb1
  UPDATE_DISCONNECTED 1
  STEP_TARGETS update
  LIST_SEPARATOR ^^
  INSTALL_COMMAND ""
  CMAKE_ARGS -DWSIZE=64
             -DRAND=UDEV
             -DSHLIB=OFF
             -DSTLIB=ON
             -DSTBIN=OFF
             -DTIMER=
             -DCHECK=off
             -DVERBS=off
             -DARITH=gmp
             -DFP_PRIME=381
             "-DFP_METHD=BASIC^^COMBA^^COMBA^^MONTY^^MONTY^^JMPDS^^SLIDE"
             "-DCFLAGS=${RELIC_CFLAGS}"
             -DFP_PMERS=off
             -DFP_QNRES=on
             "-DFPX_METHD=INTEG^^INTEG^^LAZYR"
             -DEP_PLAIN=off
             -DEP_SUPER=off
             "-DPP_METHD=LAZYR^^OATEP")

ExternalProject_Get_Property(relic BINARY_DIR)
ExternalProject_Get_Property(relic SOURCE_DIR)
include_directories(${SOURCE_DIR}/include)


file(MAKE_DIRECTORY ${BINARY_DIR}/${CMAKE_INSTALL_INCLUDEDIR}) # avoid race
                                                               # condition

if(DEFINED LIBBBS_DEBUG)
  add_compile_definitions(LIBBBS_DEBUG)
endif()



add_subdirectory(src)
add_subdirectory(test)
