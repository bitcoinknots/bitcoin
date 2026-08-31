# Upstream-derived mining sources are from OCEAN-xyz/datum_gateway commit
# dbc3b143589842feb606a409b40cd70f67117b45. See NOTICE.md and LICENSE.

find_package(Threads REQUIRED)
find_package(CURL REQUIRED)

add_library(datum_curl INTERFACE)
target_link_libraries(datum_curl INTERFACE CURL::libcurl)
if(WIN32)
  target_link_libraries(datum_curl INTERFACE bcrypt advapi32 crypt32 ws2_32)
endif()

find_path(DATUM_JANSSON_INCLUDE_DIR NAMES jansson.h REQUIRED)
find_library(DATUM_JANSSON_LIBRARY NAMES jansson REQUIRED)
add_library(DATUM::Jansson UNKNOWN IMPORTED)
set_target_properties(DATUM::Jansson PROPERTIES
  IMPORTED_LOCATION "${DATUM_JANSSON_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${DATUM_JANSSON_INCLUDE_DIR}"
)

find_path(DATUM_SODIUM_INCLUDE_DIR NAMES sodium.h REQUIRED)
find_library(DATUM_SODIUM_LIBRARY NAMES sodium libsodium REQUIRED)
add_library(DATUM::Sodium UNKNOWN IMPORTED)
set_target_properties(DATUM::Sodium PROPERTIES
  IMPORTED_LOCATION "${DATUM_SODIUM_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${DATUM_SODIUM_INCLUDE_DIR}"
)

if(WIN32)
  set(DATUM_PLATFORM_LIBRARIES)
else()
  set(DATUM_PLATFORM_LIBRARIES m)
endif()

add_library(datum_solo STATIC EXCLUDE_FROM_ALL
  datum_blocktemplates.c
  datum_coinbaser.c
  datum_embedded.c
  datum_jsonrpc.c
  datum_logger_embedded.c
  datum_protocol_solo.c
  datum_sockets.c
  datum_stratum.c
  datum_stratum_dupes.c
  datum_submitblock.c
  datum_utils.c
  thirdparty_base58.c
  thirdparty_segwit_addr.c
)

target_include_directories(datum_solo PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(datum_solo PRIVATE
  DATUM_EMBEDDED=1
  $<$<PLATFORM_ID:Windows>:CURL_STATICLIB>
)
target_link_libraries(datum_solo
  PUBLIC
    datum_curl
    DATUM::Jansson
    DATUM::Sodium
    Threads::Threads
    ${DATUM_PLATFORM_LIBRARIES}
)
