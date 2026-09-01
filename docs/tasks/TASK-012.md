# TASK-012: Mining dashboard Best Share

- Status: Implemented
- Owner: Codex root
- Source: `docs/migration-report.md`
- Depends on: TASK-011

## Objective

Add a real Best Share row to the main-window Mining summary without changing
the DATUM RPC contract.

## Scope

- Calculate achieved difficulty from each accepted share hash.
- Retain the highest value for the current DATUM session.
- Transport it through the internal C and C++ status snapshots to Qt.
- Display unavailable before the first accepted share and scientific notation
  for large values.

## Acceptance criteria

- Rejected shares never update Best Share.
- The value resets on DATUM startup and survives miner disconnects.
- `getdatuminfo` contains no Best Share field.
- The summary distinguishes Best Share from share and block counters.

## Validation commands

```bash
cmake --build /private/tmp/bitcoinpurity-b52c-gui-on --target bitcoin-qt test_bitcoin-qt bitcoind bitcoin-cli -j4
QT_QPA_PLATFORM=minimal /private/tmp/bitcoinpurity-b52c-gui-on/bin/test_bitcoin-qt
test/functional/feature_datum.py --configfile=/private/tmp/bitcoinpurity-b52c-gui-on/test/config.ini
git diff --check
```

## Validation result

- DATUM-enabled `bitcoin-qt`, `test_bitcoin-qt`, `bitcoind`, and `bitcoin-cli`
  built successfully.
- All `MiningPageTests` passed, including unavailable, integer, and scientific
  Best Share formatting.
- `feature_datum.py` passed and confirms no Best Share field was added to
  `getdatuminfo`.
- The DATUM-disabled `bitcoin-qt` build passed.
- Native screenshot inspection was deferred because the macOS desktop locked
  after the build; the updated test App binary is ready for the next launch.
