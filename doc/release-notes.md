Bitcoin Core version 29.3.knots20260207 is now available from:

  <https://bitcoinknots.org/files/29.x/29.3.knots20260207/>

This release includes various bug fixes.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoinknots/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoinknots.org/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-Qt` (on macOS)
or `bitcoind`/`bitcoin-qt` (on Linux).

Upgrading directly from very old versions of Bitcoin Core or Knots is possible,
but it might take some time if the data directory needs to be migrated. Old
wallet versions of Bitcoin Knots are generally supported.

Compatibility
==============

Bitcoin Knots is supported on operating systems using the Linux kernel, macOS
13+, and Windows 10+. It is not recommended to use Bitcoin Knots on
unsupported systems.

Known Bugs
==========

In various locations, including the GUI's transaction details dialog and the
`"vsize"` result in many RPC results, transaction virtual sizes may not account
for an unusually high number of sigops (ie, as determined by the
`-bytespersigop` policy) or datacarrier penalties (ie, `-datacarriercost`).
This could result in reporting a lower virtual size than is actually used for
mempool or mining purposes.

Due to disruption of the shared Bitcoin Transifex repository, this release
still does not include updated translations, and Bitcoin Knots may be unable
to do so until/unless that is resolved.

Notable changes
===============

Numerous wallet bugs have been fixed, including some obscure scenarios that
could delete the wallet (n.b. the ordinary-use disaster in Core 30 never
affected Knots). As a side effect, unsupported BDB versions (any other than
exactly 4.8 may experience reduced compatibility.

### P2P

- #33956 net: fix use-after-free with v2->v1 reconnection logic
- #34025 net: Waste less time in socket handling
- #34028 p2p: saturate LocalServiceInfo::nScore to prevent overflow
- #34093 netif: fix compilation warning in QueryDefaultGatewayImpl()
- Net: Reduce log level for repeated PCP/NAT-PMP NOT_AUTHORIZED failures by default

### Wallet

- #31423 wallet: migration, avoid creating spendable wallet from a watch-only legacy wallet
- #32273 wallet: Fix relative path backup during migration.
- #33268 wallet: Identify transactions spending 0-value outputs, and add tests for anchor outputs in a wallet
- #34156 wallet: fix unnamed legacy wallet migration failure
- #34226 wallet: test: Relative wallet failed migration cleanup
- #34123 wallet: migration, avoid creating spendable wallet from a watch-only legacy wallet
- #34176 wallet: crash fix, handle non-writable db directories
- #34215 wallettool: fix unnamed createfromdump failure walletsdir deletion
- #34370 wallet: Additional cleanups for migration, and fixes for createfromdump with BDB
- knots#242 Fix bugs in various BDB wallet edge cases
- knots#255 Wallet: Even if addresstype==legacy, use non-legacy change if there's no legacy sPKman
- Wallet/bdb: Use LogWarning/LogError as appropriate
- Bugfix: Fee estimation: Refactor logic to avoid unlikely unsigned overflow in TxConfirmStats::Read
- Bugfix: Wallet/bdb: Catch exceptions in MakeBerkeleyDatabase
- Wallet/bdb: improve error msg when db directory is not writable

### Mempool

- knots#246 Bugfix: txmempool: Fallback to CTxMemPoolEntry copying if Boost is too old for node extraction

### Block and transaction handling

- #34462 util: Drop *BSD headers in `batchpriority.cpp`

### GUI

- gui#899 Modernize custom filtering
- gui#924 Show an error message if the restored wallet name is empty
- knots#197 GUI: Visually move and rephrase port mapping checkboxes
- knots#244 Bugfix: GUI: Queue stylesheet changes within eventFilters
- knots#245 GUI: Minor: Fix typo in options dialog tooltip
- Revert bringToFront Wayland workaround for Qt versions >=6.3.2 with the bug fixed

### Build

- #34227 guix: Fix `osslsigncode` tests
- secp256k1#1749 build: Fix warnings in x86_64 assembly check
- depends: Qt 5.15.18

### Documentation

- #33623 doc: document capnproto and libmultiprocess deps in 29.x
- #33993 init: point out -stopatheight may be imprecise
- #34252 doc: add 433 (Pay to Anchor) to bips.md

### Test

- #32588 test: Allow testing of check failures
- #33612 test: change log rate limit version gate
- #33915 test: Retry download in get_previous_releases.py
- #33990 test: p2p: check that peer's announced starting height is remembered
- #34185 test: fix `feature_pruning` when built without wallet
- #34282 qa: Fix Windows logging bug
- #34372 QA: wallet_migration: Test several more weird scenarios
- #34369 test: Scale NetworkThread close timeout with timeout_factor

### Misc

- #29678 Bugfix: init: For first-run disk space check, round up pruned size requirement
- #32513 ci: remove 3rd party js from windows dll gha job
- #33508 ci: fix buildx gha cache authentication on forks
- #33581 ci: Properly include $FILE_ENV in DEPENDS_HASH
- #33813 Capitalise rpcbind-ignored warning message
- #33960 log: Use more severe log level (warn/err) where appropriate
- #34161 refactor: avoid possible UB from `std::distance` for `nullptr` args
- #34224 init: Return EXIT_SUCCESS on interrupt
- #34235 miniminer: stop assuming ancestor fees >= self fees
- #34253 validation: cache tip recency for lock-free IsInitialBlockDownload()
- #34272 psbt: Fix `PSBTInputSignedAndVerified` bounds `assert`
- #34293 Bugfix: net_processing: Restore missing comma between peer and peeraddr in "receive version message" and "New ___ peer connected"
- #34328 rpc: make `uptime` monotonic across NTP jumps
- #34344 ci: update GitHub Actions versions
- #34436 util: add overflow-safe `CeilDiv` helper
- bitcoin-core/leveldb-subtree#58 Initialize file_size to 0 to avoid UB
- secp256k1#1731 schnorrsig: Securely clear buf containing k or its negation
- Bugfix: Rework MSVCRT workaround to correctly exclusive-open on Windows

Credits
=======

Thanks to everyone who contributed to this release, including but not necessarily limited to:

- ANAVHEOBA
- Anthony Towns
- Antoine Poinsot
- Ataraxia
- Ava Chow
- brunoerg
- Carlo Antinarella
- codeabysss
- David Gumberg
- Eugene Siegel
- fanquake
- Felipe Micaroni Lalli
- Fonta1n3
- furszy
- glozow
- Hennadii Stepanov
- ismaelsadeeq
- jestory
- John Moffett
- Lőrinc
- Luke Dashjr
- m3dwards
- MarcoFalke
- Martin Zumsande
- Michael Dance
- Navneet Singh
- Padraic Slattery
- Patrick Strateman
- Pieter Wuille
- Russell Yanofsky
- SatsAndSports
- Sebastian Falbesoner
- sedited
- Vasil Dimov
- willcl-ark
