cmake_minimum_required(VERSION 3.10)
set(CMAKE_BUILD_TYPE Debug)

project(
  libbbs
  VERSION 0.1
  LANGUAGES C)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CheckCCompilerFlag OPTIONAL)
include(CTest)

set(CMAKE_C_STANDARD 23)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if (MSVC)
    # warning level 4
    add_compile_options(/W4)
else()
    # additional warnings
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

install(DIRECTORY "${CMAKE_SOURCE_DIR}/${CMAKE_INSTALL_INCLUDEDIR}"
        DESTINATION ${CMAKE_INSTALL_PREFIX})

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_FULL_LIBDIR}")
set(CMAKE_BUILD_WITH_RPATH TRUE)

include(ExternalProject)
ExternalProject_Add(
	blst
	PREFIX blst
	GIT_REPOSITORY https://github.com/supranational/blst.git
	GIT_TAG b79e2bc
	GIT_SHALLOW true
	#URL https://github.com/supranational/blst/archive/refs/tags/v0.3.15.tar.gz
	#DOWNLOAD_EXTRACT_TIMESTAMP false
	CONFIGURE_COMMAND ""
	BUILD_IN_SOURCE true
	BUILD_COMMAND "./build.sh"
	INSTALL_COMMAND ""
	)

ExternalProject_Get_Property(blst SOURCE_DIR)
include_directories(${SOURCE_DIR}/bindings)

find_program(MAKE_EXECUTABLE NAMES gmake make mingw32-make REQUIRED)

if(DEFINED LIBBBS_DEBUG)
  add_compile_definitions(LIBBBS_DEBUG)
endif()

# Code Coverage
if (NOT DEFINED ENABLE_CODE_COVERAGE)
  set(ENABLE_CODE_COVERAGE OFF CACHE STRING "Enable or disable code coverage" FORCE)
endif()

if (ENABLE_CODE_COVERAGE)
  message(STATUS "Code coverage enabled")

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fprofile-arcs -ftest-coverage")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -fprofile-arcs -ftest-coverage")

else()
  message(STATUS "No code coverage")
endif()

add_subdirectory(src)
add_subdirectory(test)
