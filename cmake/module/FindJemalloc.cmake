# Copyright (c) 2026-present The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

#[=======================================================================[
FindJemalloc
-----------

Finds the jemalloc headers and library.

This is a wrapper around find_package()/pkg_check_modules() commands that:
 - facilitates searching in various build environments
 - prints a standard log message

#]=======================================================================]

include(FindPackageHandleStandardArgs)

# First try to use CMake's find_package for jemalloc
find_package(Jemalloc ${Jemalloc_FIND_VERSION} NO_MODULE QUIET)
if(Jemalloc_FOUND)
  find_package_handle_standard_args(Jemalloc
    REQUIRED_VARS Jemalloc_DIR
    VERSION_VAR Jemalloc_VERSION
  )
  if(TARGET jemalloc)
    add_library(Jemalloc::Jemalloc ALIAS jemalloc)
  elseif(TARGET jemalloc-static)
    add_library(Jemalloc::Jemalloc ALIAS jemalloc-static)
  endif()
  mark_as_advanced(Jemalloc_DIR)
else()
  # Fall back to pkg-config for Unix-like systems
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(PC_Jemalloc QUIET jemalloc>=${Jemalloc_FIND_VERSION})
  endif()
  
  # If pkg-config didn't find it, try direct library search
  if(NOT PC_Jemalloc_FOUND)
    find_library(JEMALLOC_LIBRARY NAMES jemalloc)
    find_path(JEMALLOC_INCLUDE_DIR NAMES jemalloc/jemalloc.h jemalloc.h)
  else()
    set(JEMALLOC_LIBRARY ${PC_Jemalloc_LIBRARIES})
    set(JEMALLOC_INCLUDE_DIR ${PC_Jemalloc_INCLUDE_DIRS})
  endif()
  
  find_package_handle_standard_args(Jemalloc
    REQUIRED_VARS JEMALLOC_LIBRARY JEMALLOC_INCLUDE_DIR
  )
  
  if(NOT TARGET Jemalloc::Jemalloc)
    add_library(Jemalloc::Jemalloc UNKNOWN IMPORTED)
    set_target_properties(Jemalloc::Jemalloc PROPERTIES
      IMPORTED_LOCATION "${JEMALLOC_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${JEMALLOC_INCLUDE_DIR}"
    )
  endif()
  mark_as_advanced(JEMALLOC_LIBRARY JEMALLOC_INCLUDE_DIR)
endif()
