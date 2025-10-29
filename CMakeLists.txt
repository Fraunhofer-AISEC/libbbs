cmake_minimum_required(VERSION 3.10)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

project(
  libbbs
  VERSION 0.1
  LANGUAGES C)

include(CTest)
include(GNUInstallDirs)
include(ExternalProject)

set(CMAKE_C_STANDARD 23)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if (MSVC)
    # warning level 4
    add_compile_options(/W4)
else()
    # additional warnings
    add_compile_options(-Wall -Wextra -Wpedantic -Wabi)
endif()

ExternalProject_Add(
	blst
	PREFIX blst
	GIT_REPOSITORY https://github.com/supranational/blst.git
	GIT_TAG master
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
include_directories(include)
add_subdirectory(src)
add_subdirectory(test)

install(TARGETS bbs)
install(FILES include/bbs.h TYPE INCLUDE)

