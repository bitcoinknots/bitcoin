# Embedded DATUM Migration Report

## Baseline and current state

- Purity already provides GBT, submitblock, mempool, block assembly, validation,
  P2P, and network-specific consensus difficulty.
- DATUM Gateway commit `dbc3b143589842feb606a409b40cd70f67117b45`
  is available from `https://github.com/OCEAN-xyz/datum_gateway.git` and is the
  fixed upstream baseline.
- The repository initially contains no embedded DATUM sources or DATUM build
  dependencies.

## Upstream source impact

The non-pooled mining path uses block-template parsing, coinbase construction,
JSON-RPC, Stratum, duplicate-share tracking, block submission, utilities, and
address codecs. The independent daemon entry point, API/Web implementation,
Prime protocol implementation, configuration CLI, and their tests are not
runtime entry points for the embedded subsystem.

The retained solo path directly depends on curl and jansson. It also retains
libsodium's SHA-256 API through the upstream utility implementation;
`libmicrohttpd` remains Web/API-only and is excluded. CMake, depends, vcpkg,
and `BUILD_DATUM=OFF` isolate all three DATUM-only dependencies.

## Lifecycle gap

The baseline starts process-lifetime pthreads and uses infinite loops. It has no
coordinated interrupt/join path. SIGUSR1 merely requests template refresh. The
embedded implementation must add stop flags, wakeups, listener closure, and
thread joins without changing mining algorithms.

Purity starts HTTP/RPC in warmup before loading chainstate and calls
`SetRPCWarmupFinished()` near the end of node startup. DATUM must start only
after that point. Purity currently stops HTTP/RPC early in shutdown, so DATUM
interrupt/stop hooks must precede those calls.

## Security gap

Baseline Stratum authorization accepts a username without the shared-credential
policy required here, and it can emit work before the new authentication gate.
It provides fixed buffers and global client bounds, but Stage 1 additionally
needs per-IP bounds, auth timeout/cooldown, submit throttling, strict pre-auth
gating, and explicit 16 KiB line handling.

## Portability gap

The baseline socket layer uses epoll and POSIX APIs. The embedded source now
uses a bounded `poll`/`WSAPoll` adapter, native Windows socket types, and small
POSIX/Win32 thread and time wrappers while leaving Stratum parsing and
share/mining logic intact. The DATUM C target was cross-compiled with
llvm-mingw, and the complete `bitcoind.exe` was built with GNU MinGW 13 after
qualifying the Windows depends recipes. Static curl is isolated behind a small
interface target that supplies `CURL_STATICLIB` and its Windows system-library
dependencies in link-safe order.

## Data and consensus impact

No persistent format migration is required. No consensus or mempool rule may be
changed. GBT remains the source of `bits` and target, and submitblock remains the
final validation boundary. The only operator-controlled block data are the
validated fixed payout address and bounded coinbase tag.

The embedded coinbase builder preserves upstream behavior at production heights
and emits canonical `OP_1` through `OP_16` encodings for fresh test-chain heights.
An Apple M4 hashing run exposed the upstream small-height data-push encoding as
`bad-cb-height`; after the compatibility fix, the same diff-1 Stratum flow
advanced regtest from height 0 to 1 through the node's normal `submitblock`
validation path.

## Rollout

Runtime defaults off, binds loopback by default, and requires explicit secure
configuration when enabled. Stratum authentication now defaults to off for
local compatibility; `datumupnp=1` is a separate explicit UPnP opt-in and emits
a warning when used without `datumauth=1`. Release qualification requires ON/OFF builds,
disabled/enabled functional tests, protocol and abuse tests, clean shutdown,
and at least one real external SHA256d miner hashing run through production
Stratum and `submitblock` paths. Physical ASIC hardware is not required for
release acceptance; a protocol-only handshake or cross-platform build still
does not substitute for a real submitted share.

## Validation commands

Default feature build:

```bash
cmake -B build-datum -DBUILD_DATUM=ON
cmake --build build-datum -j8
```

Isolation build:

```bash
cmake -B build-no-datum -DBUILD_DATUM=OFF
cmake --build build-no-datum -j8
```

Focused runtime validation:

```bash
python3 test/functional/feature_datum.py \
  --configfile=build-datum/test/config.ini
```

Windows x64 depends build and cross-configuration:

```bash
make -C depends HOST=x86_64-w64-mingw32 \
  NO_QT=1 NO_WALLET=1 NO_ZMQ=1 NO_UPNP=1 NO_USDT=1 -j2
cmake -B build-win \
  -DCMAKE_TOOLCHAIN_FILE=depends/x86_64-w64-mingw32/toolchain.cmake \
  -DBUILD_DATUM=ON -DBUILD_GUI=OFF -DENABLE_WALLET=OFF
cmake --build build-win --target bitcoind -j2
```
