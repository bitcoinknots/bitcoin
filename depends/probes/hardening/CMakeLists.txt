cmake_minimum_required(VERSION 3.22)

project(hardening_probe CXX)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/module)

include(TryAppendCXXFlags)
include(TryAppendLinkerFlag)
include(Hardening)

set(ENABLE_HARDENING ON)
setup_hardening()

get_target_property(compile_opts hardening_interface INTERFACE_COMPILE_OPTIONS)
get_target_property(link_opts hardening_interface INTERFACE_LINK_OPTIONS)
get_target_property(workaround_opts compiler_workarounds INTERFACE_COMPILE_OPTIONS)

if(compile_opts MATCHES "-NOTFOUND$")
  set(compile_opts "")
endif()
if(link_opts MATCHES "-NOTFOUND$")
  set(link_opts "")
endif()
if(workaround_opts MATCHES "-NOTFOUND$")
  set(workaround_opts "")
endif()

list(FILTER compile_opts EXCLUDE REGEX "^-W")
list(FILTER workaround_opts EXCLUDE REGEX "^-W")

set(linker_flags "")
foreach(opt IN LISTS link_opts)
  if(opt MATCHES "^-Wl,")
    list(APPEND linker_flags "${opt}")
  endif()
endforeach()

list(JOIN compile_opts " " compile_str)
list(JOIN linker_flags " " linker_str)
list(JOIN workaround_opts " " workaround_str)

file(WRITE ${CMAKE_BINARY_DIR}/hardening.mk
  "hardening_cflags=${compile_str}\n"
  "hardening_cxxflags=${compile_str}\n"
  "hardening_ldflags=${linker_str}\n"
  "workaround_cflags=${workaround_str}\n"
  "workaround_cxxflags=${workaround_str}\n"
)
