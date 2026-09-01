# Main-window Mining Dashboard Design QA

- Source visual truth: `/Users/hsn/Downloads/1000604646.jpg`
- Implementation screenshot: `/private/tmp/bitcoinpurity-b52c-gui-on/main-window-mining-final.jpg`
- Normalized comparison: `/private/tmp/bitcoinpurity-b52c-gui-on/main-window-mining-comparison.jpg`
- Viewport: native Bitcoin-Qt main window at approximately 1080 × 600
- Source pixels: 1080 × 583
- Implementation pixels: 1079 × 602
- Narrow check: 901 × 602
- Wide check: 1217 × 630
- Runtime arguments: `-datadir=/private/tmp/bitcoinpurity-b52c-gui-on/data -port=8339`
- State: wallet loaded, main-window Mining selected, DATUM disabled, no miner hashrate or network difficulty

## Full-view comparison evidence

The normalized side-by-side comparison verifies the main-window composition:
fixed left navigation, highlighted Mining item, compact current-wallet overview
in the middle, Mining dashboard on the right, and a persistent status bar. The
middle pane is constrained to approximately 260 pixels so the three regions
track the source proportions at the reference width.

The narrow and wide captures preserve all three regions without overlap. At the
narrow size, long table descriptions elide inside their cells; at the wide size,
the dashboard expands while the wallet pane stays compact.

## Focused region comparison evidence

- Navigation: the main window shows Overview, Send, Receive, Transactions,
  Address Book, and Mining in the required order; Mining is highlighted.
- Wallet overview: the current wallet's real balance and recent transactions
  are reused in compact mode; no duplicate wallet model is introduced.
- Header and cards: title, three primary cards, and compact runtime state retain
  the reference hierarchy in the main window.
- Hashrate chart: centered title, grid, axes, and dark-theme contrast are clear;
  the empty state reflects real DATUM data instead of fabricated history.
- Share summary: all five trustworthy rows remain available in the main page.
  Bestshare is absent because `DatumStatusSnapshot` does not provide it.
- Typography: native Qt system typography preserves the source hierarchy and
  remains readable at the reference window size.
- Colors: the captured implementation follows the active macOS dark theme;
  palette-derived borders, grid lines, selected navigation, and table rows have
  sufficient contrast.
- Assets: the illustrative probability distribution is intentionally absent
  because there is no trustworthy distribution input.
- Copy: labels describe real DATUM snapshot fields rather than mock values.

## Interaction evidence

- `Alt+1` switches the main content to Overview and clears Mining selection.
- `Alt+6` returns to the main-window Mining page and highlights Mining.
- Selecting a non-Mining page removes the middle pane and restores the normal
  full-width wallet page.
- The Window menu contains Pairing and the existing address/node tools but no
  DATUM entry.
- No standalone `datumWindow` exists.

## Comparison history

### Earlier pass

- P1: validation targeted the standalone DATUM status window instead of the
  main Bitcoin-Qt window.
- P1: a Window-menu DATUM entry and separate geometry lifecycle remained.

Fixes: removed the standalone window sources, action, menu entry, geometry
state, build resources, and tests; repeated visual QA against the main window.

### Main-window pass

- P1: the first main-window implementation omitted the wallet-summary middle
  pane and stretched Mining across the entire content region.
- P2: the first three-column pass allocated 300 pixels to the middle pane,
  leaving the right dashboard narrower than the reference.

Fixes: embedded the current wallet Overview in the Mining workspace, changed
its layout to a compact vertical presentation, restored normal layout outside
Mining, and adjusted the middle pane to approximately 260 pixels.

The remaining visible differences are intentional: the active macOS dark theme
is honored, mock balances/hashrate are not fabricated, and the existing Mining
detail tabs remain available as required.

No actionable P0, P1, or P2 visual differences remain within those constraints.

final result: passed
