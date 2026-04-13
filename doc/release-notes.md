Bitcoin Knots version 29.3.knots20260415 is now available from:

  <https://bitcoinknots.org/files/29.x/29.3.knots20260415/>

This release includes the RDTS softfork (see below), new features, default
configuration changes, and various bug fixes.

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

Reduced Data Temporary Softfork
===============================

A one-year "reduced data" protocol change to the Bitcoin rules, beginning no
later than September, has been proposed and deployed by a substantial part of
the Bitcoin userbase. This upgrade fixes an existential threat to the Bitcoin
network.

Protocol changes require user consent to be effective, and if enforced
inconsistently within the community may compromise your security or others'!

If you do not know what you are doing, you can learn more at
https://bitcoinknots.org/learn/2026-rdts.

Note that to reject this softfork, you must implement your own rejection fork.
(You must make a decision either way - old versions are insecure in all
scenarios.)

This release of Bitcoin Knots fully supports RDTS when it activates.

Notable changes
===============

### Default configuration changes

- The default for `dbcache` has been adjusted to scale dynamically at startup
  for better performance on modern computers. In environments with external
  memory limits (e.g. containers), automatic sizing may not match effective
  limits. Set `-dbcache` explicitly if needed. To maintain the previous
  behavior, set `-dbcache=450`. (#34641)

### New spam filters

- Transactions creating outputs with a value less than the expected value to
  spend them (ie, "dust") are now treated by policy as if those outputs had a
  value at least meeting that threshold by having their effective fees reduced
  by the difference. This only affects tranasctions otherwise allowed by your
  node policy (it does not expand the range of accepted transactions), so
  typically this only applies to datacarrier or anchor outputs. It is enabled
  by default, and can be disabled with `subdustfeepenalty=0` (or the GUI
  option) in your configuration. (knots#272)

- Datacarrier policy options now match a newer variation of spam designed to
  bypass the prior implementation. (knots#292)

### New features

- The `sweepprivkeys` RPC method now looks for segwit (p2wpkh) and taproot
  (p2tr) UTXOs, in addition to the older p2pk and p2pkh formats. (knots#296)

- "Sweep private key" dialog added to the GUI (File menu) for easy access.
  (knots#297)

Change log
----------

### P2P

- knots#265 net: redact SOCKS5 proxy password from debug log

### Wallet

- #30221 wallet: Ensure best block matches wallet scan state
- #31953 Bugfix: RPC/Wallet: bumpfee: Avoid nullptr dereference if transaction isn't in wallet
- #32580 wallet, test: best block locator matches scan state follow-ups
- #34603 wallet: Fix detection of symlinks on Windows
- #34642 wallet: call SyncWithValidationInterfaceQueue after disconnecting chain notifications
- #34870 wallet: feebumper, fix crash when combined bump fee is unavailable
- #34888 wallet: fix amount computed as boolean in coin selection
- #34959 wallet: Enforce BDB btree levels and overflow item sizes
- knots#266 external_signer: validate fingerprint is hex before shell command use
- knots#267 codex32: early return on validation error to prevent OOB read
- knots#269 Wallet: When about to cleanup an empty directory that isn't empty, log it

### Mempool

- knots#268 Saturate CalculateExtraTxWeight and cap GUI datacarriercost to 1024

### Block and transaction handling

- #29640 Bugfix: validation: Reinsert the correct CBlockIndex in Chainstate::LoadChainTip
- #33333 coins: warn on oversized -dbcache
- #34692 Bump dbcache to 1 GiB
- #34641 node: scale default -dbcache with system RAM
- knots#238 Reduced Data Temporary Softfork, implemented as a modified BIP9 temporary deployment
- knots#272 Policy: Penalize effective fee for sub-dust outputs
- knots#292 policy: add 'opnet' to datacarriersize

### Networking

- #34093 netif: fix compilation warning in QueryDefaultGatewayImpl()
- secp256k1#1821 ellswift: fix overflow flag handling in secp256k1_ellswift_xdh

### GUI

- #34767 Bugfix: GUI/Intro: Handle errors from SelectParams the same as if during InitConfig
- gui#929 Use plurals where necessary
- gui#935 bugfix: truncate header sync percentage
- knots#214 feat(qt): add /clearhistory command
- knots#215 GUI: Port Windows taskbar progress to COM
- knots#256 Prompt user after upgrading to RDTS-enabled version
- knots#277 banman: schedule sweep at ban expiry instead of polling
- knots#287 qt: warn when script threads exceed CPU cores
- knots#288 qt: Expand sync progress bar in status bar
- knots#289 init: Inform user of upcoming RDTS softfork and lack of enforcement by this software
- knots#297 qt: Add sweep private key dialog
- Recognise service bit 27 as NODE_REDUCED_DATA / "REDUCED_DATA?"

### RPC

- #34988 rpc: fix initialization-order-fiasco by lazy-init of decodepsbt_inputs
- knots#294 blockstorage: fix unsigned underflow in GetBlockFileInfo bounds check
- knots#296 rpc: add segwit and taproot support to sweepprivkeys

### PSBT

- #34893 psbt: preserve proprietary fields when combining PSBTs

### Build

- #34612 leveldb: remove unused files
- #34776 guix: Make guix-clean more careful

### Documentation

- #34561 wallet: rpc: manpage: fix example missing fee_rate argument
- #34702 doc: Fix fee field in getblock RPC result
- knots#262 init: improve error message when index needs pruned block data
- CTxMemPoolEntry: Document when GetPriority might have a currentHeight < cachedHeight or go slightly negative

### Test

- #33118 test: fix anti-fee-sniping off-by-one error
- #34589 test: Scale feature_dbcrash.py timeout with factor
- #34622 test: assert_debug_log timeouts follow-up
- Bugfix: fuzz/wallet_bdb_parser: SeedRandomStateForTest is needed for IsDirWritable check

### Misc

- #32281 bench: Fix WalletMigration benchmark
- #32345 ipc: Handle unclean shutdowns better
- #34597 util: Fix UB in SetStdinEcho when ENOTTY
- #33152 Fix typos
- #34937 Fix startup failure with RLIM_INFINITY fd limits
- knots#295 init: clamp -lowmem to non-negative before assigning to size_t

Credits
=======

Thanks to everyone who contributed to this release, including but not necessarily limited to:

- 3c853b6299
- Andrew Toth
- Antoine Poinsot
- Ava Chow
- BitcoinMechanic
- Bortlesboat
- Dathon Ohm
- Eugene Siegel
- fanquake
- furszy
- gzJx0DuTRHytnHe7P5RmMbPf3wKy2BztweVGXTf
- Hennadii Stepanov
- Hodlinator
- Íñigo Aréjula Aísa
- ishaanam
- ismaelsadeeq
- Kyle Santiago
- Léo Haf
- Lőrinc
- Luke Dashjr
- MarcoFalke
- moneybadger1
- nervana21
- pablomartin4btc
- Pieter Wuille
- rkrux
- Ryan Ofsky
- Sjors Provoost
- SomberNight
- SpectrGen
- stickies-v
- Vasil Dimov
- w0xlt
- willcl-ark
