# Experimental DCBM Knots GUI

This branch incorporates the official Bitcoin Knots **29.4.3.knots20260508**
release (commit `a7c4617524c334f542484bfef3919b9f12573840`) while preserving
the DCBM experimental commits. The release was merged in `64eda1eb33`.

Official release:
https://github.com/bitcoinknots/bitcoin/releases/tag/v29.4.3.knots20260508

DCBM remains an explicit regtest experiment. Mainnet consensus and activation
parameters are unchanged. There is no GUI setting to activate DCBM on mainnet.

## Build

Using the already installed Qt 6 development libraries:

```sh
cmake -S . -B build -DBUILD_GUI=ON -DWITH_QT_VERSION=6 -DBUILD_GUI_TESTS=ON
cmake --build build --target bitcoin-qt test_bitcoin-qt bitcoind test_bitcoin -j 2
```

The executable is `build/bin/bitcoin-qt`. The wallet feeds reward-specific
maturity into the existing transaction status and balance displays. The
transaction-details confirmation count and transaction-icon progress now use
64 bits so that a saturated DCBM maturity cannot overflow when adding one
confirmation.

## Isolated preview

```sh
contrib/dcbm/run-gui-regtest.sh
```

The launcher creates a fresh `build/dcbm-gui.*` datadir and separate Qt
configuration/cache directories. It selects regtest with initial maturity 150,
disables wallets, peer connections and listening, and advances mock time beyond
the configured experimental expiry. It never selects existing node data.
The preview has no wallet balances; the wallet and maturity displays are
covered separately by tests. Each launch prints its datadir and preserves it
for inspection. The built executable retains ordinary Knots wallet support.

For a headless startup/shutdown check:

```sh
contrib/dcbm/run-gui-regtest.sh --smoke-test
```

This selects Qt's offscreen backend and stops after block import. Running a GUI
executable directly without an explicit datadir does not provide the launcher's
isolation; use the launcher for this experiment.

## Validation results

All four build targets completed successfully on Linux aarch64 with Qt 6.8.2.
The headless preview exited with status 0, and its isolated regtest log records
both successful initialization and `Shutdown: done`.

All six Qt test suites passed (AppTests, OptionTests, URITests, RPCNestedTests,
WalletTests, and AddressBookTests), including the new DCBM status test.
Qt tests used separate configuration, cache, data, and runtime directories:

```sh
env XDG_CONFIG_HOME=/tmp/dcbm-gui-qt-tests/config \
    XDG_CACHE_HOME=/tmp/dcbm-gui-qt-tests/cache \
    XDG_DATA_HOME=/tmp/dcbm-gui-qt-tests/share \
    XDG_RUNTIME_DIR=/tmp/dcbm-gui-qt-tests/runtime \
    QT_QPA_PLATFORM=offscreen build/bin/test_bitcoin-qt
```

The 51 coinbase-maturity, PoW, and wallet unit cases passed on the final-release
build. All five functional tests passed: `feature_dynamic_cbm_retarget.py`,
`feature_dynamic_coinbase_maturity.py`, `feature_rolling_coinbase_maturity.py`,
`mempool_long_coinbase_maturity.py`, and the official release's new
`mempool_subdust_persist.py` (23 seconds wall time, 32 accumulated).
No tests were disabled. Qt emitted the expected offscreen-platform warnings
about unsupported window operations; there were no test failures.

## Validation scope

The Qt regression test `WalletTests::dynamicCoinbaseMaturityStatus` checks that
wallet-provided remaining maturities (including INT_MAX) appear as immature,
are excluded from spendable balances, become mature, and return to immature or
not accepted after a reorganization. It complements the actual retarget and
spend validation tests documented in `dynamic-cbm-experiment.md`.

This local build is experimental and unsigned. It is not an official Knots
binary. Desktop interaction and dynamic wallet transaction details still
require manual review beyond automated tests; there is no mainnet activation
proposal in this change.
