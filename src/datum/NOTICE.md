# Embedded DATUM provenance

The upstream-derived files in this directory were copied from:

- Repository: `https://github.com/OCEAN-xyz/datum_gateway.git`
- Commit: `dbc3b143589842feb606a409b40cd70f67117b45`
- License: MIT; see `LICENSE`

Bitcoin Purity does not claim or receive rights to the DATUM or OCEAN marks.

The following baseline components are intentionally not vendored: the standalone
`main()`/daemon entry point, DATUM Prime implementation, protocol queue, Web/API,
embedded Web resources, configuration CLI, and upstream executable test entry
points.

Local modifications are limited to embedded lifecycle, fixed solo configuration,
Purity logging callbacks, authentication/resource controls, portability, and a
Prime compatibility shim. Mining algorithms and binary construction remain in
the upstream-derived C sources.

Modified upstream-derived files:

- `datum_blocktemplates.c`
- `datum_coinbaser.c`, `datum_coinbaser.h`
- `datum_conf.h`, `datum_gateway.h`, `datum_logger.h`, `datum_protocol.h`
- `datum_sockets.c`, `datum_sockets.h`
- `datum_stratum.c`, `datum_stratum.h`, `datum_stratum_dupes.c`
- `datum_submitblock.c`, `datum_submitblock.h`
- `datum_utils.c`

Copied without source changes:

- `datum_blocktemplates.h`
- `datum_jsonrpc.c`, `datum_jsonrpc.h`
- `datum_stratum_dupes.h`, `datum_utils.h`
- `thirdparty_base58.c`, `thirdparty_base58.h`
- `thirdparty_segwit_addr.c`, `thirdparty_segwit_addr.h`

Bitcoin Purity-specific files added in this directory:

- `datum_embedded.c`, `datum_embedded.h`
- `datum_logger_embedded.c`
- `datum_net.h`, `datum_thread.h`, `datum_time.h`
- `datum_protocol_solo.c`
- `CMakeLists.txt`
