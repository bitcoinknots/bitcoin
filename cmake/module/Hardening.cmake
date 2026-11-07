# Copyright (c) 2023-present The Bitcoin Core developers
# Copyright (c) 2026-present The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include_guard(GLOBAL)

function(setup_hardening)
  add_library(compiler_workarounds INTERFACE)
  try_append_cxx_flags("-fstack-reuse=none" TARGET compiler_workarounds)

  add_library(hardening_interface INTERFACE)
  target_link_libraries(hardening_interface INTERFACE compiler_workarounds)

  if(ENABLE_HARDENING)
    if(MSVC)
      try_append_linker_flag("/DYNAMICBASE" TARGET hardening_interface)
      try_append_linker_flag("/HIGHENTROPYVA" TARGET hardening_interface)
      try_append_linker_flag("/NXCOMPAT" TARGET hardening_interface)
    else()
      try_append_cxx_flags("-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
        RESULT_VAR cxx_supports_fortify_source
        SOURCE "int main() {
                # if !defined __OPTIMIZE__ || __OPTIMIZE__ <= 0
                  #error
                #endif
                }"
      )
      if(cxx_supports_fortify_source)
        target_compile_options(hardening_interface INTERFACE
          -U_FORTIFY_SOURCE
          -D_FORTIFY_SOURCE=3
        )
      endif()

      try_append_cxx_flags("-Wstack-protector" TARGET hardening_interface SKIP_LINK)
      try_append_cxx_flags("-fstack-protector-all" TARGET hardening_interface)
      try_append_cxx_flags("-fcf-protection=full" TARGET hardening_interface)

      if(NOT MINGW)
        try_append_cxx_flags("-fstack-clash-protection" TARGET hardening_interface)
      endif()

      if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
        if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
          try_append_cxx_flags("-mbranch-protection=bti" TARGET hardening_interface SKIP_LINK)
        else()
          try_append_cxx_flags("-mbranch-protection=standard" TARGET hardening_interface SKIP_LINK)
        endif()
      endif()

      try_append_linker_flag("-Wl,--enable-reloc-section" TARGET hardening_interface)
      try_append_linker_flag("-Wl,--dynamicbase" TARGET hardening_interface)
      try_append_linker_flag("-Wl,--nxcompat" TARGET hardening_interface)
      try_append_linker_flag("-Wl,--high-entropy-va" TARGET hardening_interface)
      try_append_linker_flag("-Wl,-z,relro" TARGET hardening_interface)
      try_append_linker_flag("-Wl,-z,now" TARGET hardening_interface)
      try_append_linker_flag("-Wl,-z,separate-code" TARGET hardening_interface)
      if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        try_append_linker_flag("-Wl,-fixup_chains" TARGET hardening_interface)
      endif()
    endif()
  endif()
endfunction()
