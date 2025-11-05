Bitcoin Knots version 29.2.knots20251104 is now available from:

  <https://bitcoinknots.org/files/29.x/29.2.knots20251104/>

This release includes default configuration changes and various bug fixes.

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

- The low severity service degradation vulnerability CVE-2025-46598 has been
  fixed.

- The default policy for datacarriersize has been increased to allow 83 bytes.
  While not ideal, some legacy protocols still rely on 83-byte datacarrier
  outputs, and it is undesirable to risk breaking those as Knots adoption
  grows. This is expected to be a temporary adjustment until these older
  applications can be updated to not require extra data, and will be reverted
  back to 42 in a future version. Users with a preference are encouraged to
  explicitly set it themselves.

- Memory pressure detection is no longer enabled by default. It has been found
  to misbehave in some configurations. If you wish to re-enable it, you can do
  so with the `-lowmem=<n>` configuration option.

### Consensus

- #32473 Introduce per-txin sighash midstate cache for legacy/p2sh/segwitv0 scripts

### Policy

- Default policy: Increase datacarriersize to 83 bytes

### P2P and network changes

- #33050 net, validation: don't punish peers for consensus-invalid txs
- #33105 validation: detect witness stripping without re-running Script checks
- #33738 log,blocks: avoid `GetHash()` work when logging is disabled

### GUI

- #8501 GUI: MempoolStats: Use min relay fee when mempool has none
- gui#901 qt: add createwallet and createwalletdescriptor to history filter

### Wallet

- #31514 bugfix: disallow label for ranged descriptors & allow external non-ranged descriptors to have label

### Block and transaction handling

- #19873 mempressure: Disable by default for now

### Test

- #33698 test: Use same rpc timeout for authproxy and cli

### CI

- #33639 ci: Only write docker build images to Cirrus cache

Credits
=======

Thanks to everyone who directly contributed to this release:

- /dev/fd0
- Anthony Towns
- Antoine Poinsot
- Lőrinc
- Luke Dashjr
- MarcoFalke
- Pieter Wuille
- scgbckbone
- WakeTrainDev
