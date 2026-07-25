Bitcoin Knots version 29.4.knots20260508 is now available from:

  <https://bitcoinknots.org/files/29.x/29.4.knots20260508/>

This release includes various bug fixes, performance improvements, and
extra safeguards. There are no critical fixes, so updating is not urgent.

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

This release fixes an issue where the chainstate database would repeatedly
rewrite large portions of itself, causing excessive disk reads and writes
during normal operation.

It also checks for corruption that may be caused by running old node software
after BIP110 has entered mandatory signaling. Running old node software,
including the latest version of Bitcoin Core (since it has still not yet been
updated), will no longer be a fully validating node or safe beginning
approximately 2026 August 7th. That can cause the chain-state to become
corrupted in some scenarios. This version of Knots will detect and recover
from this kind of corruption.

### Validation

- #35070 validation: prevent FindMostWorkChain from causing UB
- #35168 validation: Don't add pruned blocks to `m_blocks_unlinked` on startup
- #35465 coins: compact chainstate regularly
- knots#323 validation: keep script cache enabled when RDTS deployment inactive
- knots#350 validation: correct inherited RDTS-invalid blocks at startup

### Leveldb

- #61(bitcoin-core/leveldb): Disable seek compaction

### Net

- #30951 Misc v2onlyclearnet updates
- #34028 p2p: Saturate LocalServiceInfo::nScore updates at INT_MAX
- #35117 i2p: Don't log raw SAM replies
- #35825 net: only count connections in AddConnection when the type has a limit
- knots#348 net: Update mainnet seeds and scripts
- knots#352 Fix spawning Tor subprocess when datadir contains spaces
- net: tolerate stale BIP-110 outbound peers as additional connections

### Wallet

- #35228 wallet: use outpoint when estimating input size
- knots#320 descriptor: reject OP_IF/OP_NOTIF in Taproot miniscript under reduced-data

### GUI

- knots#301 GUI: Show warnings on all tabs
- knots#330 GUI/NetWatch: Fix heap corruption from off-thread model mutation
- knots#332 GUI: Don't assert on translated field labels in ReceiveRequestDialog
- knots#336 GUI: Use locale-aware GUIUtil::dateTimeStr for datetime fields
- knots#344 GUI: Keep the RPC console on the wallet it is set to

### RPC

- policy: don't let ignore_rejects relax reduced-data consensus flags

### Build

- #34228 depends: Unset SOURCE_DATE_EPOCH in gen_id script
- #34848 cmake: Migrate away from deprecated SQLite3 target
- knots#309 Bugfix: Build fails to enable ARM CPU crypto extensions
- knots#339 cmake: Check PIE link support for C
- knots#345 depends: update libevent to 2.1.13-stable
- depends: Qt 5.15.19

### Test

- #27052 QA: p2p_block_times: test behaviour of a stale block in block announcement time tracking
- #34918 fuzz: [refactor] Remove unused g_setup pointers
- #35164 test: cover P2SH sigop counting in test_witness_sigops

### Doc

- #34510 doc: fix broken bpftrace installation link
- #34671 doc: Update Guix install for Debian/Ubuntu
- #35283 doc: mention -DWITH_ZMQ=ON in BSD build guides

### CI

- #35202 ci: restore sockets in i686, no IPC job
- #35378 ci: switch runners from cirrus to warpbuild
- #35408 ci: 35378 followups
- knots#328 ci: install librsvg2-bin and imagemagick for test each commit

### Misc

- #35384 util: Check write failures before renaming settings.json
- knots#329 contrib: don't use the default datadir in gen-bitcoin-conf.sh

Credits
=======

Thanks to everyone who directly contributed to this release:

- /dev/fd0
- andrewtoth
- codeabysss
- Daniel Pfeifer
- darosior
- fanquake
- Hennadii Stepanov
- jayvaliya
- junbyjun1238
- Kyle Santiago
- Léo Haf
- Lőrinc
- Luke Dashjr
- Marco De Leon
- MarcoFalke
- Maxime
- Musa Haruna
- naiyoma
- Philip D'Ath
- Shrey
- stratospher
- takeshikurosawaa
- ToRyVand
- willcl-ark
