# Copyright (c) 2026 The Bitcoin Purity developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include_guard(GLOBAL)

# Host triplet suffix for deploy packages, e.g. arm64-apple-darwin.
function(get_deploy_host_triplet result_var)
  if(CMAKE_CROSSCOMPILING AND CMAKE_C_COMPILER_TARGET)
    set(triplet "${CMAKE_C_COMPILER_TARGET}")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
      set(triplet "arm64-apple-darwin")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
      set(triplet "x86_64-apple-darwin")
    else()
      set(triplet "${CMAKE_SYSTEM_PROCESSOR}-apple-darwin")
    endif()
  elseif(MINGW OR CMAKE_SYSTEM_NAME STREQUAL "Windows")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
      set(triplet "x86_64-w64-mingw32")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
      set(triplet "i686-w64-mingw32")
    else()
      set(triplet "${CMAKE_SYSTEM_PROCESSOR}-w64-mingw32")
    endif()
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
      set(triplet "x86_64-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
      set(triplet "aarch64-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm|armv7l|armv7)$")
      set(triplet "arm-linux-gnueabihf")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "s390x")
      set(triplet "s390x-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^ppc64le")
      set(triplet "powerpc64le-linux-gnu")
    else()
      execute_process(
        COMMAND ${PROJECT_SOURCE_DIR}/depends/config.guess
        OUTPUT_VARIABLE guessed
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
      )
      if(guessed MATCHES "^([^-]+-[^-]+-[^-]+)")
        set(triplet "${CMAKE_MATCH_1}")
      else()
        set(triplet "${CMAKE_SYSTEM_PROCESSOR}-linux-gnu")
      endif()
    endif()
  else()
    string(TOLOWER "${CMAKE_SYSTEM_NAME}" system_name)
    set(triplet "${CMAKE_SYSTEM_PROCESSOR}-${system_name}")
  endif()
  set(${result_var} "${triplet}" PARENT_SCOPE)
endfunction()
