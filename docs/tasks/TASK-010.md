# TASK-010: Qt left navigation and mining dashboard

## Goal

Replace the wallet GUI's horizontal navigation with a fixed left rail, embed a
two-tab Address Book, and add a read-only DATUM Mining dashboard.

## Requirements

- Navigation order is Overview, Send, Receive, Transactions, Address Book, and
  Mining; Pairing moves to the Window menu.
- Mining mode uses the reference three-region main-window composition with a
  compact current-wallet Overview column beside the dashboard; other wallet
  pages remain full width.
- Address Book embeds Sending and Receiving views without removing the existing
  standalone address windows.
- `BUILD_DATUM=ON` adds a dashboard backed only by `DatumStatusSnapshot`, with a
  bounded non-persistent 24-hour hashrate graph and existing detail views.
- `BUILD_DATUM=OFF` includes no Mining action, page, or resources.
- Mining status is available only from the main-window navigation; no
  standalone DATUM window or Window-menu entry remains.

## Verification

Build and run `bitcoin-qt` and `test_bitcoin-qt` with DATUM enabled, configure
and build the GUI with DATUM disabled, run `git diff --check`, and visually
inspect the main window at narrow, reference, and wide sizes.

## Validation result

- `BUILD_DATUM=ON`: `bitcoin-qt`, `test_bitcoin-qt`, `bitcoind`, and
  `bitcoin-cli` built successfully; all Qt tests passed with the offscreen
  platform.
- `feature_datum.py` passed, including disabled startup, authentication,
  difficulty hot reload, input bounds, and shutdown.
- `BUILD_DATUM=OFF`: `bitcoin-qt` built successfully and the resulting Qt
  library contains no `MiningPage` or `gotoMiningPage` symbols.
- Native Cocoa inspection passed against the main Bitcoin-Qt window at the
  reference size. `Alt+1`/`Alt+6` switched Overview and Mining, the Window menu
  exposed no DATUM status entry, and the normalized design comparison passed.
