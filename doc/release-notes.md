Bitcoin Knots version 29.3.knots20260508 is now available from:

  <https://bitcoinknots.org/files/29.x/29.3.knots20260508/>

This release includes the RDTS softfork ([**IMPORTANT INFORMATION BELOW**](#reduced-data-temporary-softfork)), new
features, default configuration changes, and various bug fixes.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoinknots/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoinknots.org/list/announcements/join/>

How to Upgrade
==============

**Before upgrading,** read [the Reduced Data Temporary Softfork section below](#reduced-data-temporary-softfork),
and if you run the bitcoind server, be sure to add the `consensusrules=rdts`
parameter to your `bitcoin.conf` file.

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

This version of Bitcoin Knots applies the BIP110 (RDTS) network upgrade, which fixes critical vulnerabilities in long-standing network design. To avoid applying this upgrade by accident, this version asks for explicit confirmation.

Important: Because this upgrade already has broad community support, skipping this update or reverting to an older software version does not reject it. Running outdated software after any network upgrade only leaves your node vulnerable to displaying fake or fraudulent transactions. To effectively reject this upgrade, you need to run alternative software designed to split away from the upgraded network.

To confirm this upgrade, click 'OK' on the GUI startup prompt, or add to your bitcoin.conf file:

  consensusrules=rdts

If you are not ready to adopt the RDTS upgrade yet, you can download this same version of Bitcoin Knots without RDTS support (though as noted above, doing so does not reject the upgrade) from:

  <https://bitcoinknots.org/files/29.x/29.3.knots20260507/>

For more information, see:

  <https://bitcoinknots.org/learn/2026-rdts>

Notable changes
===============

### Default configuration changes

- When `-dbcache` is not set explicitly, Bitcoin Knots now chooses a RAM-aware
  default between 100 MiB and 2 GiB. The selected `-dbcache` value is still
  used for both IBD and steady-state operation and unused mempool allocation
  may be shared with this cache. In environments with external memory limits
  (e.g. containers), automatic sizing may not match effective limits. The
  previous behavior can be restored by setting `-dbcache` explicitly. (#34641)

- Block creation now demands a progressively higher feerate as the block fills
  up, in the spirit of Satoshi's original client, so a block is only extended
  when the space is paid for. The new `-blockmintxfeerampstart` option is the
  percentage a block must be filled to before `-blockmintxfee` starts being
  scaled up, defaulting to `50` as it did originally. Unlike the original, which
  jumped straight to twice the minimum feerate at that point, the requirement
  rises continuously from the unscaled minimum. Setting it to `100` restores the
  previous behaviour, and it has no effect if `-blockmintxfee` is set to `0`.
  (knots#338)

### New spam filters

- Transactions creating outputs with a value less than the expected value to
  spend them (ie, "dust") are now treated by policy as if those outputs had a
  value at least meeting that threshold by having their effective fees reduced
  by the difference. This only affects transactions otherwise allowed by your
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

### P2P and network changes

- Tor hidden services that are created automatically by Bitcoin Knots will have
  [PoW defenses](https://tpo.pages.torproject.net/onion-services/ecosystem/technology/security/pow/)
  enabled if the Tor daemon supports that. (#33414)

Change log
----------

### Wallet

- #30221 wallet: Ensure best block matches wallet scan state
- #31953 Bugfix: RPC/Wallet: bumpfee: Avoid nullptr dereference if transaction isn't in wallet
- #32580 wallet, test: best block locator matches scan state follow-ups
- #34603 wallet: Fix detection of symlinks on Windows
- #34642 wallet: call SyncWithValidationInterfaceQueue after disconnecting chain notifications
- #34870 wallet: feebumper, fix crash when combined bump fee is unavailable
- #34888 wallet: fix amount computed as boolean in coin selection
- #34959 wallet: Enforce BDB btree levels and overflow item sizes
- #35227 wallet: check the final BDB page LSN during migration
- knots#266 external_signer: validate fingerprint is hex before shell command use
- knots#267 codex32: early return on validation error to prevent OOB read
- knots#269 Wallet: When about to cleanup an empty directory that isn't empty, log it

### Block and transaction handling

- #29640 Bugfix: validation: Reinsert the correct CBlockIndex in Chainstate::LoadChainTip
- #33333 coins: warn on oversized -dbcache
- #34692 Bump dbcache to 1 GiB
- #34641 node: scale default -dbcache with system RAM
- #35209 validation: correct lifetime of precomputed tx data
- knots#238 Reduced Data Temporary Softfork, implemented as a modified BIP9 temporary deployment
- knots#268 Saturate CalculateExtraTxWeight and cap GUI datacarriercost to 1024
- knots#272 Policy: Penalize effective fee for sub-dust outputs
- knots#292 policy: add 'opnet' to datacarriersize

### Networking

- #33414 tor: enable PoW defenses for automatically created hidden services
- #34093 netif: fix compilation warning in QueryDefaultGatewayImpl()
- #35087 tor: limit torcontrol line size that is processed to prevent OOM
- #35116 net: cleanup SOCKS5 auth logging
- #35117 i2p: clean up SESSION CREATE error logging
- secp256k1#1821 ellswift: fix overflow flag handling in secp256k1_ellswift_xdh
- torcontrol: Enforce MAX_LINE_LENGTH even on completed lines
- Bugfix: torcontrol: Attempt to reconnect after MAX_LINE_LENGTH-triggered disconnection
- chainparams: Remove DNS seed hosted by PT

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
- knots#297 qt: Add sweep private key dialog
- Recognise service bit 27 as NODE_REDUCED_DATA / "REDUCED_DATA?"

### REST & RPC

- #29016 Bugfix: rest: Handle /rest/mempool/transactions parse error
- #34988 rpc: fix initialization-order-fiasco by lazy-init of decodepsbt_inputs
- knots#294 blockstorage: fix unsigned underflow in GetBlockFileInfo bounds check
- knots#296 rpc: add segwit and taproot support to sweepprivkeys

### PSBT

- #34893 psbt: preserve proprietary fields when combining PSBTs

### Build

- #34612 leveldb: remove unused files
- #34776 guix: Make guix-clean more careful
- #35197 guix: add -Wl,--icf=safe to darwin build
- build: Workaround incompatibilities with Boost 1.91
- depends: bump miniupnpc to 2.3.4_pre20260407
- Bugfix: build: If sanitizers are enabled, we cannot link with --no-undefined
- Bugfix: libbitcoinkernel: Add missing external_lib_interface

### Documentation

- #34561 wallet: rpc: manpage: fix example missing fee_rate argument
- #34702 doc: Fix fee field in getblock RPC result
- #35076 doc: clarify pruning impact on wallet sync
- knots#262 init: improve error message when index needs pruned block data
- CTxMemPoolEntry: Document when GetPriority might have a currentHeight < cachedHeight or go slightly negative

### Test

- #33118 test: fix anti-fee-sniping off-by-one error
- #34158 QA: Add tests for torcontrol
- #34589 test: Scale feature_dbcrash.py timeout with factor
- #34622 test: assert_debug_log timeouts follow-up
- #35161 test: check merkle mutation root invariant
- #35164 test: cover P2SH sigop counting in test_witness_sigops
- #35218 test: fix P2SH script in coins cache fuzz target
- Bugfix: fuzz/wallet_bdb_parser: SeedRandomStateForTest is needed for IsDirWritable check

### Misc

- #32281 bench: Fix WalletMigration benchmark
- #32345 ipc: Handle unclean shutdowns better
- #34597 util: Fix UB in SetStdinEcho when ENOTTY
- #33152 Fix typos
- #34937 Fix startup failure with RLIM_INFINITY fd limits
- #35097 util: Return uint64_t from _MiB and _GiB operators
- #35195 coins: cache UTXO outpoint hash codes
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
- David Gumberg
- Eugene Siegel
- Fabian Jahr
- fanquake
- furszy
- gzJx0DuTRHytnHe7P5RmMbPf3wKy2BztweVGXTf
- Hennadii Stepanov
- Hodlinator
- Íñigo Aréjula Aísa
- ishaanam
- ismaelsadeeq
- janb84
- Kyle Santiago
- Léo Haf
- Lőrinc
- Luke Dashjr
- MarcoFalke
- Memetic Money
- moneybadger1
- Musa Haruna
- nervana21
- optout
- pablomartin4btc
- Pieter Wuille
- rkrux
- Ryan Ofsky
- Sjors Provoost
- SomberNight
- SpectrGen
- stickies-v
- takeshikurosawaa
- Vasil Dimov
- w0xlt
- willcl-ark
