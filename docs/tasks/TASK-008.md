# TASK-008: Qt DATUM mining status window

## Status

Superseded by [TASK-010](TASK-010.md). The standalone Window-menu DATUM window
was removed; its status views now live only in the main-window Mining page.

## Goal

Originally added a singleton read-only DATUM window under the Bitcoin-Qt
`Window` menu and the bounded runtime snapshots needed by both the GUI and
aggregate RPC. The snapshot work remains; the window requirement does not.

## Historical acceptance criteria (superseded)

- `BUILD_DATUM=ON` includes the action and window; OFF builds include neither.
- The visible window refreshes every second and stops refreshing while hidden.
- Overview, connected miners, current job/template, mapping, and block-submit
  diagnostics are shown without exposing credentials.
- Worker name, remote IP, and user agent remain GUI-only.
- Session share/block counters survive miner disconnect and reset at DATUM
  startup; no cross-restart persistence or history charts are added.
- `getdatuminfo` remains backward compatible and adds non-secret aggregate
  session, mapping, job, and block-submit fields.

## Verification

Build Bitcoin-Qt and the functional test target with DATUM enabled, run the Qt
action/singleton test and DATUM RPC/Stratum tests, and configure an OFF build to
confirm the conditional source and menu boundary.
