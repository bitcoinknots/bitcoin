# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include_guard(GLOBAL)
include(GNUInstallDirs)

function(install_binary_component component)
  cmake_parse_arguments(PARSE_ARGV 1
    IC                        # prefix
    "HAS_MANPAGE;HAS_ZSH_COMPLETION"  # options
    ""                        # one_value_keywords
    ""                        # multi_value_keywords
  )
  set(target_name ${component})
  install(TARGETS ${target_name}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT ${component}
  )
  if(INSTALL_MAN AND IC_HAS_MANPAGE)
    install(FILES ${PROJECT_SOURCE_DIR}/doc/man/${target_name}.1
      DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
      COMPONENT ${component}
    )
  endif()
  if(INSTALL_ZSH_COMPLETION AND IC_HAS_ZSH_COMPLETION)
    # Zsh completion files must be prefixed with underscore
    install(FILES ${PROJECT_SOURCE_DIR}/contrib/completions/zsh/${target_name}.zsh
      DESTINATION ${CMAKE_INSTALL_DATADIR}/zsh/site-functions
      RENAME _${target_name}
      COMPONENT ${component}
    )
  endif()
endfunction()
