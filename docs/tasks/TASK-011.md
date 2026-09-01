# TASK-011: Mining dashboard data collection and calculations

- Status: Implemented
- Owner: Codex root
- Source: `docs/migration-report.md`
- Depends on: TASK-002, TASK-004, TASK-010

## Objective

Back the main-window Mining dashboard with cumulative accepted work and a
deterministic five-minute rolling hashrate estimate while preserving the
existing DATUM RPC contract.

## Scope

- Accumulate accepted share difficulty for the current DATUM session and carry
  it through the internal C and C++ status snapshots.
- Sample the cumulative value once per visible minute and calculate aggregate
  miner hashrate, network hashrate, and chance per block in Qt.
- Preserve a bounded 24-hour GUI-local trend with explicit gaps across hidden
  periods and DATUM sessions.
- Keep current share-rejection, block-candidate, job, and miner-detail sources.

## Out of scope

- New or changed `getdatuminfo` fields.
- DATUM protocol, configuration, consensus, payout, or block-submission changes.
- Persistent mining history or fabricated Bestshare values.

## Implementation checklist

- [x] Add and reset the atomic session accepted-difficulty counter.
- [x] Extend only the internal DATUM status structures.
- [x] Add the five-minute Qt tracker and derived calculations.
- [x] Integrate unavailable, baseline, ready, stop, and session-change states.
- [x] Add deterministic Qt and DATUM regression coverage.
- [x] Verify DATUM-enabled and DATUM-disabled builds and native GUI behavior.

## Acceptance criteria

- The first estimate appears only after at least one visible minute and a
  positive accepted-work delta.
- Hashrate uses actual elapsed time and at most five minutes of checkpoints.
- Hidden time, counter regression, and a new DATUM session never contribute to
  the next estimate.
- Invalid or incomplete inputs display as unavailable; no zero samples are
  fabricated for disabled or stopped DATUM.
- The cumulative counter survives miner disconnect, resets on DATUM startup,
  and is absent from `getdatuminfo`.

## Validation commands

```bash
cmake --build /private/tmp/bitcoinpurity-b52c-gui-on --target bitcoin-qt test_bitcoin-qt bitcoind bitcoin-cli -j4
QT_QPA_PLATFORM=minimal /private/tmp/bitcoinpurity-b52c-gui-on/bin/test_bitcoin-qt
test/functional/feature_datum.py --configfile=/private/tmp/bitcoinpurity-b52c-gui-on/test/config.ini
cmake --build /private/tmp/bitcoinpurity-b52c-gui-off --target bitcoin-qt -j4
git diff --check
```

## Validation result

- DATUM-enabled `bitcoin-qt`, `test_bitcoin-qt`, `bitcoind`, and `bitcoin-cli`
  built successfully in `/private/tmp/bitcoinpurity-b52c-gui-on`.
- Deterministic `MiningPageTests` passed under Qt's minimal platform. The macOS
  minimal plugin intentionally skips existing native `AppTests`.
- `feature_datum.py` passed and asserts the internal accepted-difficulty value
  is absent from `getdatuminfo`.
- DATUM-disabled `bitcoin-qt` built successfully in
  `/private/tmp/bitcoinpurity-b52c-gui-off`; the resulting binary contains none
  of the Mining dashboard strings or internal counter symbol.
- The main window was launched with
  `-datadir=/private/tmp/bitcoinpurity-b52c-gui-on/data -port=8339` plus regtest
  DATUM arguments. A real Apple GPU SHA256d miner authorized at difficulty 1
  and submitted accepted shares. After one visible minute the dashboard showed
  143.2 MH/s for a two-difficulty delta, matching
  `2 * 2^32 / 60 seconds`; a later post-hide baseline produced 141.4 MH/s from
  its actual non-integral interval.
- Native inspection confirmed live height, accepted/rejected/stale summaries,
  block candidates, miner telemetry, job details, 100% regtest probability,
  and 0.00333 H/s derived regtest network hashrate. Hiding and reopening Mining
  returned to Collecting baseline and preserved a graph gap.
- A native disabled-DATUM run showed Disabled with unavailable hashrate,
  probability, height, and all current-job fields. No stale job data remained.
- Runtime inspection exposed and fixed three presentation issues: positive
  sub-GH/s values rounded to zero, the fixed TH/s trend axis clipped low-rate
  values, and QFormLayout compressed long job and diagnostic values. The final
  native rerun displayed a 236.2 MH/s adaptive graph scale and complete detail
  values.
- Direct shell-launched Cocoa `AppTests` still exit in the host service with
  `no screens available`; this is separate from the successfully inspected
  application-bundle run through the active desktop session.
