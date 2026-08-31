# TASK-005: Qt Settings parity and DATUM tab

- Status: Complete
- Owner: Codex root
- Depends on: TASK-001, TASK-002, TASK-003, TASK-004

## Objective

Keep the Bitcoin-Qt Settings surface identical to upstream/master while adding
an additive DATUM configuration tab for `BUILD_DATUM=ON` builds.

## Acceptance evidence (2026-08-25)

- `git diff --no-index` of the pre-DATUM `optionsdialog.cpp`, `optionsdialog.h`,
  `optionsdialog.ui`, and `optionsmodel.*` against `upstream-master` produced no
  differences.
- The DATUM tab exposes all `SetupDatumArgs` runtime settings and validates the
  listen address, bounds, payout address, authentication, and loopback RPC URL.
- Wallet-enabled macOS arm64 build passed with `BUILD_GUI=ON`,
  `ENABLE_WALLET=ON`, and `BUILD_DATUM=ON`.
- Re-deployed and signed bundle:
  `/private/tmp/bitcoinpurity-build-qt-wallet/dist/Bitcoin-Qt.app`.
- `codesign --verify --deep --strict` passed and the executable contains the
  DATUM Settings strings.
- A headless visual launch was not claimed: this host's Qt `minimal` plugin
  aborts while loading application fonts, and the `offscreen` plugin is not
  packaged in the bundle. Source parity, compilation, bundle deployment, and
  signing were verified independently.
