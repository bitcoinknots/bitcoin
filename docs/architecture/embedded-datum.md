# Embedded DATUM Architecture

## Stage 1 boundary

```text
External SHA256d miner (ASIC or GPU)
    | Stratum V1
    v
bitcoinpurityd
    |-- Purity node, mempool, BlockAssembler, validation, P2P
    `-- C++ datum bridge
          `-- upstream-derived DATUM C subsystem
                | localhost HTTP JSON-RPC
                v
          Purity getblocktemplate / submitblock
```

Purity-specific code is confined to the bridge, argument registration,
lifecycle hooks, validation notification, and optional status RPC. DATUM C must
not include Purity C++ headers. When `BUILD_DATUM=ON`, Bitcoin-Qt adds a DATUM
configuration tab alongside the unchanged upstream Settings surface. The tab
writes runtime values through `ArgsManager`; sensitive DATUM credentials remain
out of `settings.json`.

The C subsystem exposes a bounded status snapshot through `datum_embedded.h`.
The C++ bridge converts it to a typed `DatumStatusSnapshot`; the Qt Mining page
and `getdatuminfo` consume that snapshot so aggregate values use one source of
truth. A separate bounded miner array is requested only by the local GUI. The
GUI timer runs once per second while visible and never exposes miner identity
through RPC.

`WalletFrame` owns the wallet-independent Mining page and a horizontal Mining
workspace. In Mining mode, the current `WalletView` is switched to a compact
Overview presentation in the workspace's fixed-width wallet column, while the
Mining page occupies the remaining width. Leaving Mining hides that column
composition and restores the normal full-width wallet page. Each `WalletView`
owns its two-tab Address Book page. `BitcoinGUI` owns the exclusive navigation
actions and presents them in a fixed left toolbar. Mining status has no separate
window lifecycle or geometry; it is reachable only from the main-window
navigation.

The C status layer atomically accumulates the actual difficulty of every
accepted share for the current DATUM session. The internal snapshot transports
that cumulative value to Qt without adding an RPC field. While visible, the
Mining page records one checkpoint per minute and estimates miner hashrate as
`delta_accepted_difficulty * 2^32 / elapsed_seconds`, using up to five minutes
of checkpoints. Hiding the page or changing DATUM sessions resets the rate
baseline so hidden time is never included.

A bounded in-memory queue stores at most 1,440 timestamped graph entries and is
discarded with the GUI. Session changes and sampling pauses introduce graph
gaps instead of synthetic zero samples. Chance per block is the GUI-derived
miner hashrate divided by the network hashrate inferred as
`network_difficulty * 2^32 / 600`; invalid or incomplete inputs produce no
value. For each accepted share, the C status layer also calculates achieved
difficulty from the submitted hash and atomically retains the session maximum.
The internal snapshot exposes this Best Share value to Qt only; DATUM startup
resets it and miner disconnects do not.

## Ownership and lifecycle

Purity owns construction, startup, interruption, stop, and destruction. Startup
occurs after RPC warmup finishes and chainstate is ready. Interruption first
closes the Stratum listener and wakes workers. Stop joins all DATUM-owned
threads before HTTP/RPC teardown.

When `datumupnp=1`, the C++ bridge owns a separate interruptible port-mapping
worker. It first uses miniupnpc to discover a valid IPv4 IGD, then falls back
to PCP/NAT-PMP when the router does not advertise an IGD. It maps only the
configured DATUM Stratum TCP port, renews the mapping, retries operational
failures, and removes the UPnP mapping during clean shutdown (PCP/NAT-PMP
leases expire naturally). This mapping is independent of the node's P2P
`-upnp` worker and is rejected for loopback or IPv6-only DATUM listeners.
The bridge records requested versus active mapping state, protocol, external
endpoint, lease lifetime, update time, and a sanitized error. miniupnpc queries
the external address after mapping; PCP/NAT-PMP use the returned mapping.

Session share totals are the sum of connected-miner counters and counters
captured at disconnect under a snapshot lock. They reset at DATUM startup and
do not require persistent storage. Current jobs and miners are copied under the
existing bounded Stratum locks. Template and primary block-submit results are
stored as sanitized fixed-size status records.
Session accepted difficulty is an atomic cumulative work counter updated only
after successful share validation. It resets with the other session statistics
and therefore survives miner disconnect without additional per-miner lifetime
state.

An `UpdatedBlockTip` listener calls a C ABI refresh function. The function only
sets the same bounded refresh state used by the baseline SIGUSR1 handler; the
template thread continues to fetch GBT over localhost RPC and retains periodic
refresh.

The `setdatumdiff` RPC and the Qt share-difficulty field write the new share
difficulty to a C11 atomic runtime value. Each Stratum worker observes that
value in its own event loop and sends the updated difficulty and a clean current
job from the worker thread, avoiding cross-thread socket-buffer access. The Qt
payout address and Coinbase tag use a mutex-protected C runtime snapshot; the
bridge swaps both values together and requests the same bounded template
refresh, so new jobs use the new coinbase without restarting DATUM. The three
values are persisted for the next startup, and none changes the GBT network
target.

## Dependency direction

```text
bitcoin_node -> datum_bridge (C++) -> datum_solo (C)
                                     -> curl
                                     -> jansson
                                     -> platform socket/thread primitives
                                     -> miniupnpc (when `WITH_MINIUPNPC=ON` and
                                        `datumupnp=1` is used)
                                     -> PCP/NAT-PMP (fallback)
```

Prime/protocol encryption and Web/API sources are excluded. `libmicrohttpd` is
therefore absent; libsodium remains only because the retained upstream utility
code uses its SHA-256 API. All DATUM-only dependencies are conditional on
`BUILD_DATUM` and are represented in CMake, depends, and vcpkg.

## Portability constraint

The baseline socket implementation is epoll/POSIX-specific and its daemon
threads are intentionally process-lifetime. The embedded implementation uses a
bounded `poll`/`WSAPoll` adapter plus small POSIX/Win32 thread and time wrappers,
alongside auditable lifecycle hooks. These adapters do not change Stratum
parsing or mining/share logic.

## Stage 2 seam

The bridge API may later replace HTTP JSON-RPC with C callbacks backed by node
interfaces. Stage 1 must not expose Purity C++ types to DATUM C or implement that
optimization.
