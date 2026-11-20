Bitcoin Knots version 29.5.1.knots20260508 is now available from:

  <https://bitcoinknots.org/files/29.x/29.5.1.knots20260508/>

This release includes various bug fixes and spam filter improvements.

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

Security
--------

- CVE-2026-117348 has been fixed: A peer could stall a node, stopping it from
  processing blocks and transactions for a time, by repeatedly announcing an
  orphan transaction with many missing parents. (#35878)

- On systems with `-walletnotify` configured, an authenticated RPC caller
  allowed to create wallets could execute arbitrary commands as the node
  process account by crafting a wallet name with regex replacement
  characters. Wallet notification placeholder replacement now treats wallet
  names literally. (#36048)

Policy
------

- Out of range values for several policy options (`bytespersigop`,
  `bytespersigopstrict`, `maxscriptsize`, `limitancestorsize`, and
  `limitdescendantsize`) will now error at startup. (knots#298)

- Keys now count toward the datacarrier limit unless signatures are actually
  verified against them, so decoy keys can no longer carry data past the limit.
  (knots#470)

RPC
---

- `testmempoolaccept` and `submitpackage` now correctly apply the
  `spkreuse=conflict` policy. (knots#514)

### Policy and spam filters

- knots#298 Bugfix: Check bounds of bytespersigop[strict], maxscriptsize, and limit{ancestor,descendant}size params
- knots#470 policy: credit a pubkey only when a signature verified against it
- knots#514 policy: Reject script reuse between transactions submitted as one package

### Net

- #35878 net_processing: process unique tx INVs only
- knots#502 net: Let feelers through while stale peers hold the outbound target
- knots#508 torcontrol: Reap launched Tor processes and back off between launches

### Wallet

- #34358 wallet: fix removeprunedfunds bug with conflicting transactions
- #36048 util: keep wallet names literal in notification commands
- #36339 wallet: avoid int overflow in listtransactions

### GUI

- gui#944 Fix out-of-bounds read in RPCParseCommandLine on empty command

### RPC

- #20551 rpc: Refuse inbound as an addnode connection type

### Misc

- #36286 crypto: Fix MuHash3072 division by itself
- knots#520 Refactor: Split BIP110 rules into individual flags

### Tests

- knots#513 test: fix a feeler race in p2p_blake2b_outbound_slots case E
- knots#509 End testnet4 long_coinbase_maturity at block 154801 instead of 158111

Credits
=======

Thanks to everyone who directly contributed to this release:

- 2rdzy
- Fabian Jahr
- Gregory Sanders
- Jason Sopko
- Josiah Glosson
- Kanan
- Kyle Santiago
- Lionel Wardhaugh
- Lőrinc
- Luke Dashjr
- MarcoFalke
- Martin Zumsande
- Sayed Nabhan
- Rob Hamilton
