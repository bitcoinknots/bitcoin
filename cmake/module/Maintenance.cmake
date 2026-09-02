# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include_guard(GLOBAL)

include(DeployHostTriplet)

function(setup_split_debug_script)
  if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    set(OBJCOPY ${CMAKE_OBJCOPY})
    set(STRIP ${CMAKE_STRIP})
    configure_file(
      contrib/devtools/split-debug.sh.in split-debug.sh
      FILE_PERMISSIONS OWNER_READ OWNER_EXECUTE
                       GROUP_READ GROUP_EXECUTE
                       WORLD_READ
      @ONLY
    )
  endif()
endfunction()

function(add_maintenance_targets)
  if(NOT PYTHON_COMMAND)
    return()
  endif()

  foreach(target IN ITEMS bitcoind bitcoin-qt bitcoin-cli bitcoin-tx bitcoin-util bitcoin-wallet test_bitcoin bench_bitcoin)
    if(TARGET ${target})
      list(APPEND executables $<TARGET_FILE:${target}>)
    endif()
  endforeach()

  add_custom_target(check-symbols
    COMMAND ${CMAKE_COMMAND} -E echo "Running symbol and dynamic library checks..."
    COMMAND ${PYTHON_COMMAND} ${PROJECT_SOURCE_DIR}/contrib/devtools/symbol-check.py ${executables}
    VERBATIM
  )

  add_custom_target(check-security
    COMMAND ${CMAKE_COMMAND} -E echo "Checking binary security..."
    COMMAND ${PYTHON_COMMAND} ${PROJECT_SOURCE_DIR}/contrib/devtools/security-check.py ${executables}
    VERBATIM
  )
endfunction()

function(add_windows_deploy_target)
  if(MINGW AND TARGET bitcoin-qt AND TARGET bitcoind AND TARGET bitcoin-cli AND TARGET bitcoin-tx AND TARGET bitcoin-wallet AND TARGET bitcoin-util AND TARGET test_bitcoin)
    # TODO: Consider replacing this code with the CPack NSIS Generator.
    #       See https://cmake.org/cmake/help/latest/cpack_gen/nsis.html
    get_deploy_host_triplet(deploy_host_triplet)
    set(DEPLOY_HOST_TRIPLET ${deploy_host_triplet})
    include(GenerateSetupNsi)
    generate_setup_nsi()
    set(WIN64_SETUP_EXE bitcoin-win64-setup-${CLIENT_VERSION_STRING}-${deploy_host_triplet}.exe)
    # Always delete and recreate: an OUTPUT rule would skip rm when the installer
    # already exists, and makensis / zip would then append to the old package.
    add_custom_target(deploy
      COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/release
      COMMAND ${CMAKE_STRIP} $<TARGET_FILE:bitcoin-qt> -o ${PROJECT_BINARY_DIR}/release/$<TARGET_FILE_NAME:bitcoin-qt>
      COMMAND ${CMAKE_STRIP} $<TARGET_FILE:bitcoind> -o ${PROJECT_BINARY_DIR}/release/$<TARGET_FILE_NAME:bitcoind>
      COMMAND ${CMAKE_STRIP} $<TARGET_FILE:bitcoin-cli> -o ${PROJECT_BINARY_DIR}/release/$<TARGET_FILE_NAME:bitcoin-cli>
      COMMAND ${CMAKE_STRIP} $<TARGET_FILE:bitcoin-tx> -o ${PROJECT_BINARY_DIR}/release/$<TARGET_FILE_NAME:bitcoin-tx>
      COMMAND ${CMAKE_STRIP} $<TARGET_FILE:bitcoin-wallet> -o ${PROJECT_BINARY_DIR}/release/$<TARGET_FILE_NAME:bitcoin-wallet>
      COMMAND ${CMAKE_STRIP} $<TARGET_FILE:bitcoin-util> -o ${PROJECT_BINARY_DIR}/release/$<TARGET_FILE_NAME:bitcoin-util>
      COMMAND ${CMAKE_STRIP} $<TARGET_FILE:test_bitcoin> -o ${PROJECT_BINARY_DIR}/release/$<TARGET_FILE_NAME:test_bitcoin>
      COMMAND ${CMAKE_COMMAND} -E rm -f ${PROJECT_BINARY_DIR}/${WIN64_SETUP_EXE}
      COMMAND makensis -V2 ${PROJECT_BINARY_DIR}/bitcoin-win64-setup.nsi
      DEPENDS
        generate_nsis_images
        bitcoin-qt
        bitcoind
        bitcoin-cli
        bitcoin-tx
        bitcoin-wallet
        bitcoin-util
        test_bitcoin
      BYPRODUCTS ${PROJECT_BINARY_DIR}/${WIN64_SETUP_EXE}
      COMMENT "Creating ${WIN64_SETUP_EXE}"
      VERBATIM
    )
  endif()
endfunction()

function(add_macos_deploy_target)
  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND TARGET bitcoin-qt)
    set(macos_app "Bitcoin-Qt.app")
    # Stage bundle metadata outside the .app so it is restored on every deploy.
    # configure_file into the .app is lost if that directory is deleted.
    set(osx_bundle_meta ${PROJECT_BINARY_DIR}/osx-bundle)
    configure_file(${PROJECT_SOURCE_DIR}/share/qt/Info.plist.in ${osx_bundle_meta}/Info.plist NO_SOURCE_PERMISSIONS)
    file(CONFIGURE OUTPUT ${osx_bundle_meta}/PkgInfo CONTENT "APPL????")
    file(CONFIGURE OUTPUT ${osx_bundle_meta}/empty.lproj CONTENT "")
    file(CONFIGURE OUTPUT ${osx_bundle_meta}/InfoPlist.strings
      CONTENT "{ CFBundleDisplayName = \"@CLIENT_NAME@\"; CFBundleName = \"@CLIENT_NAME@\"; }"
    )

    set(bitcoin_icns ${PROJECT_BINARY_DIR}/src/qt/res/rendered_icons/bitcoin.icns)
    set(bitcoin_icns_dest ${PROJECT_BINARY_DIR}/${macos_app}/Contents/Resources/bitcoin.icns)
    add_custom_command(
      OUTPUT ${bitcoin_icns_dest}
      COMMAND ${CMAKE_COMMAND} -E copy ${bitcoin_icns} ${bitcoin_icns_dest}
      DEPENDS generate_icns
      VERBATIM
    )
    add_custom_target(bitcoin_icns_deployed DEPENDS "${bitcoin_icns_dest}")

    add_custom_command(
      OUTPUT ${PROJECT_BINARY_DIR}/${macos_app}/Contents/MacOS/Bitcoin-Qt
      COMMAND ${CMAKE_COMMAND} -E rm -rf
        ${PROJECT_BINARY_DIR}/${macos_app}/Contents/Frameworks
        ${PROJECT_BINARY_DIR}/${macos_app}/Contents/PlugIns
        ${PROJECT_BINARY_DIR}/${macos_app}/Contents/_CodeSignature
      COMMAND ${CMAKE_COMMAND} -E make_directory ${macos_app}/Contents/Resources/Base.lproj
      COMMAND ${CMAKE_COMMAND} -E copy ${osx_bundle_meta}/Info.plist ${macos_app}/Contents/Info.plist
      COMMAND ${CMAKE_COMMAND} -E copy ${osx_bundle_meta}/PkgInfo ${macos_app}/Contents/PkgInfo
      COMMAND ${CMAKE_COMMAND} -E copy ${osx_bundle_meta}/empty.lproj ${macos_app}/Contents/Resources/empty.lproj
      COMMAND ${CMAKE_COMMAND} -E copy ${osx_bundle_meta}/InfoPlist.strings ${macos_app}/Contents/Resources/Base.lproj/InfoPlist.strings
      COMMAND ${CMAKE_COMMAND} --install ${PROJECT_BINARY_DIR} --config $<CONFIG> --component bitcoin-qt --prefix ${macos_app}/Contents/MacOS --strip
      COMMAND ${CMAKE_COMMAND} -E rename ${macos_app}/Contents/MacOS/bin/$<TARGET_FILE_NAME:bitcoin-qt> ${macos_app}/Contents/MacOS/Bitcoin-Qt
      COMMAND ${CMAKE_COMMAND} -E rm -rf ${macos_app}/Contents/MacOS/bin
      COMMAND ${CMAKE_COMMAND} -E rm -rf ${macos_app}/Contents/MacOS/share
      DEPENDS
        bitcoin-qt
        ${osx_bundle_meta}/Info.plist
        ${osx_bundle_meta}/PkgInfo
        ${osx_bundle_meta}/empty.lproj
        ${osx_bundle_meta}/InfoPlist.strings
      VERBATIM
    )

    string(REPLACE " " "-" osx_volname ${CLIENT_NAME})
    get_deploy_host_triplet(deploy_host_triplet)
    set(osx_zip_name "${osx_volname}-${CLIENT_VERSION_STRING}-${deploy_host_triplet}")
    set(macos_zip_app "${CLIENT_NAME}.app")
    if(NOT QT_TRANSLATIONS_DIR)
      foreach(_qt_ver 5 6)
        if(DEFINED Qt${_qt_ver}_DIR)
          get_filename_component(_qt_prefix "${Qt${_qt_ver}_DIR}/../../.." ABSOLUTE)
          if(EXISTS "${_qt_prefix}/translations")
            set(QT_TRANSLATIONS_DIR "${_qt_prefix}/translations")
            break()
          endif()
        endif()
      endforeach()
    endif()
    set(macdeploy_args ${macos_app} ${osx_zip_name} -zip-app-name ${CLIENT_NAME})
    if(QT_TRANSLATIONS_DIR)
      list(APPEND macdeploy_args -translations-dir=${QT_TRANSLATIONS_DIR})
    endif()
    if(CMAKE_HOST_APPLE)
      # Always delete and recreate. An OUTPUT rule skips the whole command
      # (including rm) when the zip already exists and dependencies are unchanged.
      add_custom_target(deploydir
        COMMAND ${CMAKE_COMMAND} -E rm -f ${PROJECT_BINARY_DIR}/${osx_zip_name}.zip
        COMMAND ${CMAKE_COMMAND} -E rm -rf ${PROJECT_BINARY_DIR}/dist
        COMMAND ${CMAKE_COMMAND} -E rm -rf "${PROJECT_BINARY_DIR}/${CLIENT_NAME}.app"
        COMMAND ${PYTHON_COMMAND} ${PROJECT_SOURCE_DIR}/contrib/macdeploy/macdeployqtplus ${macdeploy_args} -zip
        DEPENDS
          ${PROJECT_BINARY_DIR}/${macos_app}/Contents/MacOS/Bitcoin-Qt
          ${bitcoin_icns_dest}
        BYPRODUCTS ${PROJECT_BINARY_DIR}/${osx_zip_name}.zip
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        COMMENT "Creating ${osx_zip_name}.zip"
        VERBATIM
      )
      add_custom_target(deploy)
    else()
      add_custom_command(
        OUTPUT ${PROJECT_BINARY_DIR}/dist/${macos_app}/Contents/MacOS/Bitcoin-Qt
        COMMAND OBJDUMP=${CMAKE_OBJDUMP} ${PYTHON_COMMAND} ${PROJECT_SOURCE_DIR}/contrib/macdeploy/macdeployqtplus ${macdeploy_args}
        DEPENDS
          ${PROJECT_BINARY_DIR}/${macos_app}/Contents/MacOS/Bitcoin-Qt
          ${bitcoin_icns_dest}
        VERBATIM
      )
      add_custom_target(deploydir
        DEPENDS ${PROJECT_BINARY_DIR}/dist/${macos_app}/Contents/MacOS/Bitcoin-Qt
      )

      find_program(ZIP_COMMAND zip REQUIRED)
      add_custom_target(deploy
        COMMAND ${CMAKE_COMMAND} -E rm -f ${PROJECT_BINARY_DIR}/dist/${osx_zip_name}.zip
        COMMAND ${PROJECT_SOURCE_DIR}/cmake/script/macos_zip.sh ${ZIP_COMMAND} ${osx_zip_name}.zip ${macos_zip_app}
        DEPENDS ${PROJECT_BINARY_DIR}/dist/${macos_app}/Contents/MacOS/Bitcoin-Qt
        BYPRODUCTS ${PROJECT_BINARY_DIR}/dist/${osx_zip_name}.zip
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/dist
        COMMENT "Creating ${osx_zip_name}.zip"
        VERBATIM
      )
    endif()
    add_dependencies(deploydir bitcoin-qt)
    add_dependencies(deploydir bitcoin_icns_deployed)
    add_dependencies(deploy deploydir)
  endif()
endfunction()
