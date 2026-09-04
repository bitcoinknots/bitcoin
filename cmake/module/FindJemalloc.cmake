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
  find_package(PkgConfig REQUIRED)
  if(Jemalloc_FIND_VERSION)
    set(_jemalloc_pc_arg "jemalloc>=${Jemalloc_FIND_VERSION}")
  else()
    set(_jemalloc_pc_arg "jemalloc")
  endif()
  pkg_check_modules(PC_Jemalloc QUIET IMPORTED_TARGET ${_jemalloc_pc_arg})
  find_package_handle_standard_args(Jemalloc
    REQUIRED_VARS PC_Jemalloc_FOUND
    VERSION_VAR PC_Jemalloc_VERSION
  )
  if(Jemalloc_FOUND)
    add_library(Jemalloc::Jemalloc ALIAS PkgConfig::PC_Jemalloc)
  endif()
endif()