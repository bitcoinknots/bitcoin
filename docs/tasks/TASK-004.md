# TASK-004: Protocol, build, lifecycle, and external-miner verification

- Status: Complete
- Owner: Codex root
- Source: `docs/migration-report.md`
- Depends on: TASK-001, TASK-002, TASK-003

## Objective

Qualify the complete Stage 1 feature and report each acceptance criterion with
evidence.

## Scope

- Automated ON/OFF, disabled/config, protocol, robustness, and shutdown tests.
- Enabled regtest integration with GBT/job/share/block-submit evidence.
- Linux, macOS arm64, and Windows x64 build evidence.
- External SHA256d miner hashing and share/block-submit acceptance run.

## Acceptance and validation

Report each required check as passed, failed, blocked, or not run, with the exact
command and evidence. Do not substitute a build or protocol-only handshake for
a real external-miner hashing and share-submission run.

## Current evidence (2026-08-25)

| Check | Status | Evidence |
|---|---|---|
| macOS arm64, `BUILD_DATUM=ON` | Passed | `cmake --build /private/tmp/bitcoinpurity-build-datum-portable --target bitcoind bitcoin-cli -j8` |
| macOS arm64, `BUILD_DATUM=OFF` | Passed | `cmake --build /private/tmp/bitcoinpurity-build-datum-off --target bitcoind -j8`; OFF binary contains no `getdatuminfo`, `datum_solo`, or `datumpassword` marker. |
| Functional protocol/security/lifecycle | Passed | `python3 test/functional/feature_datum.py --configfile=/private/tmp/bitcoinpurity-build-datum-portable/test/config.ini --tmpdir=/private/tmp/feature_datum_final11`; includes extended config validation, rate-bounded rejected-share logging, and canonical BIP34 `OP_1` coinbase-height coverage. |
| Manual embedded listener/miner handshake | Passed without hashing hardware | Started `bitcoind` on regtest with `-datumlisten=0.0.0.0 -datumport=33334`; `lsof` showed PID 22643 (`bitcoind`) as the sole listener. A socket client completed `mining.subscribe`, authorized as `testminer.worker1`, and received `mining.set_difficulty` plus `mining.notify`. `getdatuminfo` reported the configured listener and difficulty. Shutdown logged `[datum] subsystem stopped` and the listener disappeared. Evidence directory: `/private/tmp/datum-manual.kwoRBR`. |
| External Apple GPU Stratum miner | Passed | Apple M4 `metal_nonce_finder` connected as `testminer.gpuminer`, authorized, received diff-1 work, hashed at roughly 130–200 MH/s, and submitted a share with hash `00000000ced630b29727e4438e1f5268c73f21954247e3396b2824c08f900d12`. The node accepted it with `block=yes`, logged successful upstream submission, advanced regtest from height 0 to 1, and reported the same best-block hash. This run exposed and verified the fix for canonical BIP34 encoding at heights 1–16. Evidence: `/private/tmp/datum-gpu-fixed.Yohfv1` and `/private/tmp/datum-gpu-acceptance.acgP4y/miner.log`. |
| Windows x64 DATUM dependencies | Passed | `make -C depends HOST=x86_64-w64-mingw32 NO_QT=1 NO_WALLET=1 NO_ZMQ=1 NO_UPNP=1 NO_USDT=1 -j8` with llvm-mingw. |
| Windows x64 DATUM C/C++ units | Passed | `datum_solo`, `mining/datum_bridge.cpp.obj`, and `rpc/datum.cpp.obj` cross-compiled. |
| Windows x64 full daemon | Passed | Ubuntu 24.04 arm64 container with GNU MinGW 13: clean Windows depends build followed by `cmake --build /tmp/build-win-gcc --target bitcoind -j2`. Final output `/private/tmp/bitcoinpurity-win-gcc-final/bitcoind.exe` is PE32+ x86-64, SHA-256 `cb7341b3d6435643bef0efa05da7e983ba184b50ecbb10db81cbdcb1ab926dec`. The earlier llvm-mingw/libc++ attempt remains an alternate-toolchain incompatibility, not the platform result. |
| Linux arm64 build/runtime | Passed | Ubuntu 24.04 container: `cmake --build /tmp/build-datum --target bitcoind bitcoin-cli -j2`, then `python3 /work/test/functional/feature_datum.py --configfile=/tmp/build-datum/test/config.ini --tmpdir=/tmp/feature_datum_linux3`; tests successful with the canonical small-height coinbase fix. |
| Physical ASIC | Not required | Current acceptance policy permits the completed external Apple GPU SHA256d hashing run. Common ASIC protocol compatibility remains a product requirement, but physical ASIC hardware is not a release gate. |
