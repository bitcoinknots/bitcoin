0.21.1 Release Notes
====================

Bitcoin Knots version *0.21.1.knots20210629* is now available from:

  <https://bitcoinknots.org/files/0.21.x/0.21.1.knots20210629/>

This release includes new features, various bug fixes and performance
improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoinknots/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoinknots.org/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-Qt` (on Mac)
or `bitcoind`/`bitcoin-qt` (on Linux).

Upgrading directly from a version of Bitcoin Knots that has reached its EOL is
possible, but it might take some time if the data directory needs to be migrated. Old
wallet versions of Bitcoin Knots are generally supported.

Compatibility
==============

Bitcoin Knots is supported on operating systems using the Linux kernel,
macOS 10.12+, and Windows 7 and newer. It is not recommended to use
Bitcoin Knots on unsupported systems.

From Bitcoin Knots 0.20.0 onwards, macOS versions earlier than 10.12 are no
longer supported.

Users running macOS Catalina should "right-click" and then choose "Open" to
open the Bitcoin Knots .dmg. This is due to new signing requirements and
privacy violations imposed by Apple, which the Bitcoin Knots project does not
implement.

Notable changes
===============

Taproot Soft Fork
-----------------

Included in this release are mainnet and testnet activation
parameters for the taproot soft fork (BIP341) which also adds support
for schnorr signatures (BIP340) and tapscript (BIP342).

Activation parameters in Bitcoin Knots are compatible with both the
[original Taproot activation client](https://bitcointaproot.cc) as well as
Bitcoin Core 0.21.1. Bitcoin Knots also includes a checkpoint to ensure
miners cannot rewrite the established blockchain history to cancel Taproot.
(As always, users may opt to disable all checkpoints with the
`-checkpoints=0` option, but this is *not* recommended.)

Taproot will be activate at block 709632, expected in early or mid November.
When activated, these improvements will allow users of single-signature
scripts, multisignature scripts, and complex contracts to all use
identical-appearing commitments that enhance their privacy and the
fungibility of all bitcoins. Spenders will enjoy lower fees and the
ability to resolve many multisig scripts and complex contracts with the
same efficiency, low fees, and large anonymity set as single-sig users.
Taproot and schnorr also include efficiency improvements for full nodes
such as the ability to batch signature verification.  Together, the
improvements lay the groundwork for future potential
upgrades that may improve efficiency, privacy, and fungibility further.

This release includes the ability to pay taproot addresses, although
payments to such addresses are not secure until taproot activates.
It also includes the ability to relay and mine taproot transactions
after activation.  Beyond those two basic capabilities, this release
does not include any code that allows anyone to directly use taproot.
The addition of taproot-related features to Bitcoin Knots's wallet is
expected in later releases.

All users, businesses, and miners are encouraged to upgrade to this
release (or a subsequent compatible release) unless they object to
activation of taproot.  Upgrading before
block 709632 is highly recommended to help enforce taproot's new rules
and to avoid the unlikely case of seeing falsely confirmed transactions.

Miners will need to ensure they update
their nodes before block 709632 or non-upgraded nodes could cause them to mine on
an invalid chain.

Anyone who objects to activation of Taproot should also act before November
to ensure they do not follow the Taproot-active chain with reduced security.
Assuming the Bitcoin community generally has accepted Taproot, doing so will
entail creating a new altcoin, and should be given an entirely new name to
avoid any confusion. Replay protection is recommended if any wish to avail
themselves of this option. Note that Bitcoin Knots does not intend to support
any such altcoins; plan accordingly.


For more information about taproot, please see the following resources:

- Technical specifications
  - [BIP340 Schnorr signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) 
  - [BIP341 Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
  - [BIP342 Validation of Taproot scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)

- Popular articles;
  - [Taproot Is Coming: What It Is, and How It Will Benefit Bitcoin](https://bitcoinmagazine.com/technical/taproot-coming-what-it-and-how-it-will-benefit-bitcoin)
  - [What do Schnorr Signatures Mean for Bitcoin?](https://academy.binance.com/en/articles/what-do-schnorr-signatures-mean-for-bitcoin)
  - [The Schnorr Signature & Taproot Softfork Proposal](https://blog.bitmex.com/the-schnorr-signature-taproot-softfork-proposal/)

- Development history overview
  - [Taproot](https://bitcoinops.org/en/topics/taproot/)
  - [Schnorr signatures](https://bitcoinops.org/en/topics/schnorr-signatures/)
  - [Tapscript](https://bitcoinops.org/en/topics/tapscript/)
  - [Soft fork activation](https://bitcoinops.org/en/topics/soft-fork-activation/)

- Other
  - [Original Taproot activation client and simple explanation](https://bitcointaproot.cc/)
  - [Questions and answers related to taproot](https://bitcoin.stackexchange.com/questions/tagged/taproot)
  - [Taproot review](https://github.com/ajtowns/taproot-review)

GUI changes
-----------

- Bitcoin Knots will now attempt to re-theme itself when the operating
  system's colour palette changes. While not all platforms are supported, this
  should fix usability when using macOS's "Dark Mode" toggle.

- The payment request details dialog has been reverted to use a single text
  area for easy copying of the entire details.

- Several improvements have been made the debug window, particularly the Peers
  tab.

- Experimental descriptor wallets can now create backups in a text-based
  "database dump" format. The default remains the raw wallet copy format
  for now; to try the new format, change the file type in the Backup Wallet
  dialog. (gui#230)

Updated RPCs
------------

- Due to [BIP 350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
  being implemented, behavior for all RPCs that accept addresses is changed when
  a native witness version 1 (or higher) is passed. These now require a Bech32m
  encoding instead of a Bech32 one, and Bech32m encoding will be used for such
  addresses in RPC output as well. No version 1 addresses should be created
  for mainnet until consensus rules are adopted that give them meaning
  (e.g. through [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)).
  Once that happens, Bech32m is expected to be used for them, so this shouldn't
  affect any production systems, but may be observed on other networks where such
  addresses already have meaning (like signet).

- The `validateaddress` RPC now optionally returns an `error_locations` array,
  with the indices of invalid characters in the address. For example, this
  will return the locations of up to two Bech32 errors. The older
  `error_index` result, which returned only a single error, is now deprecated.

- Wallet RPC methods `listtransactions`, `listsinceblock`, and
  `gettransaction` will, for unconfirmed transactions, now include an
  `in_mempool` field indicating if this node's memory pool has accepted it.
  (#21260)

- For extra safety, RPC users configured with access restricted to a single
  wallet are no longer able to call the `dumptxoutset`, `importwallet`,
  `dumpwallet`, or `backupwallet` RPC methods.

- `getblockchaininfo` now provides signalling details for LOCKED_IN softforks.
  An additional `period_start` field has also been added. (#21934, #22016)

- The `fundrawtransaction` method now has an `include_unsafe` option to use
  inputs that are not considered safe to spend. (#21359)

- The `getnodeaddresses` RPC now returns a `network` field indicating the
  network type (ipv4, ipv6, onion, or i2p) for each address.  (#21594)

- `getnodeaddresses` now also accepts a `network` argument (ipv4, ipv6, onion,
  or i2p) to return only addresses of the specified network.  (#21843)

- The `listbanned` RPC now returns two new numeric fields: `ban_duration` and
  `time_remaining`. Respectively, these new fields indicate the duration of a
  ban and the time remaining until a ban expires, both in seconds. (#21602)

- `listdescriptors` will now, if the wallet is unlocked, return `desc` in
  normalized descriptor form.

- `getblockstats` adds two new fields, `utxo_increase_actual` and
  `utxo_size_inc_actual`, similar to the existing `utxo_increase` and
  `utxo_size_inc`, but not counting datacarrier (OP_RETURN) outputs. (#19888)

- The fee histogram optionally provided by `getmempoolinfo` can now be
  configured with a list of fee rates to group by. The output format remains
  the same for now, but is expected to change in a future release.

New RPCs
--------

- An experimental `maxmempool` RPC method has been added to allow for
  adjusting the maximum memory pool size limit without restarting the node.
  (#21780)

- A new `removeaddress` RPC will remove a watch only address or script
  from the current wallet. (#15129)

- To fetch blocks explicitly from a known peer, a new `getblockfrompeer`
  method can be used. (#20295)

- `addconnection` has been added, similar to `addnode`. (#19315)

Tools and Utilities
-------------------

- A new CLI `-addrinfo` command returns the number of addresses known to the
  node per network type (including Tor v2 versus v3) and total. This can be
  useful to see if the node knows enough addresses in a network to use options
  like `-onlynet=<network>` or to upgrade to current and future Tor releases
  that support Tor v3 addresses only.  (#21595)

- A new `-rpcwaittimeout` argument to `bitcoin-cli` sets the timeout
  in seconds to use with `-rpcwait`. If the timeout expires,
  `bitcoin-cli` will report a failure. (#21056)

- The `bitcoin-wallet` tool can now create descriptor wallets using the new
  `-descriptors` option. (#21277)

Miscellaneous
-------------

- The `-walletnotify` feature will now replace `%b` with the hash and `%h`
  with the height, both of the block seen confirming the transaction. For
  unconfirmed transactions, they will be "unconfirmed" and -1, respectively.
  (##21141)

- It is now possible to set `reindex=auto` in the `bitcoin.conf` file to
  automatically reindex when/if the chainstate database is determined to be
  corrupted. (#22072)

- The `mempool.dat` file has been reverted back to the format used by Bitcoin
  Core, while manual coin-age prioritisation changes (not supported by Core)
  have been moved into a parallel `mempool-knots.dat` file (which will not
  be created until it has something to store).

0.21.1 change log
=================

Detailed release notes follow. This overview includes changes that affect
behavior, not code moves, refactors and string updates. Changes specific to
Bitcoin Knots (beyond Core) are flagged with an asterisk ('*') before the
description.

### Consensus
- #21377 Speedy trial support for versionbits (ajtowns)
- #21686 Speedy trial activation parameters for Taproot (achow101)
- n/a *Enforce checkpoints at their specific block height (luke-jr)
- n/a *Update checkpoints and chain params, adding a new checkpoint at block 688,888 (luke-jr)

### P2P protocol and network code
- #20852 allow CSubNet of non-IP networks (vasild)
- #21043 Avoid UBSan warning in ProcessMessage(…) (practicalswift)
- #19884 *No delay in adding fixed seeds if -dnsseed=0 and peers.dat is empty (dhruv)
- #21644 *bugfix: use NetPermissions::HasFlag() in CConnman::Bind() (jonatack)
- #22013 *ignore block-relay-only peers when skipping DNS seed (ajtowns)
- #22096 *AddrFetch - don't disconnect on self-announcements (mzumsande)
- #20254 *Bugfix: Initialise NET_I2P to unreachable without -i2pproxy set (luke-jr)
- #20254 *net: recognize I2P from ParseNetwork() so that -onlynet=i2p works (luke-jr)
- #22211 *relay I2P addresses even if not reachable (by us) (vasild)
- #19763 *don't try to relay to the address' originator (vasild)
- #21327 *ignore transactions while in IBD (glozow)
- #22147 *Protect last outbound HB compact block peer (sdaftuar)
- #22288 *Resolve Tor control plane address (adriansmares)

### Wallet
- #21166 Introduce DeferredSignatureChecker and have SignatureExtractorClass subclass it (achow101)
- #21083 Avoid requesting fee rates multiple times during coin selection (achow101)
- #20202 *Make BDB support optional (achow101)
- #21907 *Do not iterate a directory if having an error while accessing it (hebasto)
- #21944 *Fix issues when walletdir is root directory (prayank23)
- #22308 *Add missing BlockUntilSyncedToCurrentChain (MarcoFalke)
- #18842 *Mark replaced tx to not be in the mempool anymore (MarcoFalke)
- #22359 *Do not set fInMempool in transactionAddedToMempool when tx is not in the mempool (MarcoFalke)
- #21277 *listdescriptors uses normalized descriptor form (S3RK)
- #20275 *List BDB wallets in non-BDB builds (luke-jr)
- #15129 *Added ability to remove watch only addresses (benthecarman)
- #20365 *wallettool: add parameter to create descriptors wallet (S3RK)
- #21141 *Add new format string placeholders for walletnotify (maayank)
- #21260 *indicate whether a transaction is in the mempool (danben)
- #21359 *rpc: include_unsafe option for fundrawtransaction (t-bast)
- #10615 *RPC: Further restrict wallet-restricted users's access (luke-jr)

### RPC and other APIs
- #21201 Disallow sendtoaddress and sendmany when private keys disabled (achow101)
- n/a *Bugfix: RPC: Actually accept deprecated param names (luke-jr)
- #18466 *fix invalid parameter error codes for {sign,verify}message RPCs (theStack)
- #19888 *Improve getblockstats for unspendables (fjahr)
- #21192 *cli: Treat high detail levels as maximum in -netinfo (laanwj)
- #19315 *addconnection RPC method (amitiuttarwar)
- #21934 *getblockchaininfo: Include versionbits signalling details during LOCKED_IN (luke-jr)
- #22016 *add period_start to version bits statistics (Sjors)
- #21422 *Add feerate histogram to getmempoolinfo (kiminuo)
- #21594 *add network field to getnodeaddresses (jonatack)
- #21843 *enable GetAddr, GetAddresses, and getnodeaddresses by network (jonatack)
- #20295 *getblockfrompeer (Sjors)
- #21319 *Optimise getblock for simple disk->hex case (luke-jr)
- #21056 *Add a -rpcwaittimeout parameter to limit time spent waiting (cdecker)
- #21173 *util: faster HexStr => 13% faster blockToJSON (martinus)
- #21595 *cli: create -addrinfo (jonatack)
- #21602 *add additional ban time fields to listbanned (jarolrod)
- #21780 *Add maxmempool RPC (rebroad)
- #20832 *Better error messages for invalid addresses (eilx2)
- #16807 *Let validateaddress locate multiple errors in Bech32 address (meshcollider)

### GUI
- gui#152 *Initialise DBus notifications in another thread (luke-jr)
- gui#202 *peers-tab: bug fix right panel toggle (RandyMcMillan)
- gui#204 *Drop buggy TableViewLastColumnResizingFixer class (hebasto)
- gui#217 *Make warning label look clickable (jarolrod)
- gui#236 *Bugfix: Allow the user to start anyway when loading a wallet errors (luke-jr)
- gui#243 *fix issue when disabling the auto-enabled blank wallet checkbox (jarolrod)
- gui#271 *Don't clear console prompt when font resizing (jarolrod)
- gui#276 *Elide long strings in their middle in the Peers tab (hebasto)
- gui#280 *Remove user input from URI error message (prayank23)
- gui#325 *Align numbers in the "Peer Id" column to the right (hebasto)
- gui#329 *Make console buttons look clickable (jarolrod)
- gui#275 *Support runtime appearance adjustment on macOS (hebasto)
- gui#366 *Enable palette change adaptation on all platforms (luke-jr)
- gui#319 *Paste button in Open URI dialog (kristapsk)
- gui#291 *Network Graph layout - debug window improvement (RandyMcMillan)
- gui#180 *display plain "Inbound" in peer details (jonatack)
- gui#363 *Make Peers table aware of runtime palette change (luke-jr)
- gui#213 *Add Copy Address Action to Payment Requests (jarolrod)
- gui#214 *Disable requests context menu actions when appropriate (jarolrod)
- gui#205 *Save/restore TransactionView and recentRequestsView tables column sizes (hebasto)
- gui#206 *Display fRelayTxes and bip152_highbandwidth_{to, from} in peer details (jonatack)
- gui#226 *Add "Last Block" and "Last Tx" rows to peer details area (jonatack)
- gui#230 *Support backup to new text-based database dump format (luke-jr)
- gui#281 *set shortcuts for console's resize buttons (jarolrod)
- gui#293 *Enable wordWrap for Services (RandyMcMillan)
- gui#298 *Peertableview alternating row colors (RandyMcMillan)
- gui#307 *Make row color alternating in the Peers tab optional (hebasto)
- gui#309 *Add access to the Peers tab from the network icon (hebasto)
- gui#318 *Add Copy address Peers Tab Context Menu Action (jarolrod)
- gui#343 *Improve the GUI responsiveness when progress dialogs are used (hebasto)
- gui#362 *Add keyboard shortcuts to context menus (luke-jr)
- n/a *Point out MULTIPLE positions of invalid characters in Bech32 addresses (luke-jr)
- n/a *Convert payment request to show in QTextEdit (luke-jr)

### Build system
- #21486 link against -lsocket if required for `*ifaddrs` (fanquake)
- #20983 Fix MSVC build after gui#176 (hebasto)
- #21882 *Fix undefined reference to __mulodi4 (hebasto)
- #20938 *fix linking against -latomic when building for riscv (fanquake)
- #21920 *improve macro for testing -latomic requirement (MarcoFalke)
- #22159 *Add --with-append-cxxflags option (MarcoFalke)

### Tests and QA
- #21380 Add fuzzing harness for versionbits (ajtowns)
- #20812 fuzz: Bump FuzzedDataProvider.h (MarcoFalke)
- #20740 fuzz: Update FuzzedDataProvider.h from upstream (LLVM) (practicalswift)
- #21446 Update vcpkg checkout commit (sipsorcery)
- #21397 fuzz: Bump FuzzedDataProvider.h (MarcoFalke)
- #21081 Fix the unreachable code at `feature_taproot` (brunoerg)
- #20562 Test that a fully signed tx given to signrawtx is unchanged (achow101)
- #21571 Make sure non-IP peers get discouraged and disconnected (vasild, MarcoFalke)
- #21489 fuzz: cleanups for versionbits fuzzer (ajtowns)
- #22279 *fuzz: add missing ECCVerifyHandle to base_encode_decode (apoelstra)
- #22137 *util: Properly handle -noincludeconf on command line (take 2) (MarcoFalke)
- #21785 *Fix intermittent issue in p2p_addr_relay.py (MarcoFalke)
- #21822 *resolve bug in interface_bitcoin_cli.py (klementtan)
- #22311 *Add missing syncwithvalidationinterfacequeue in p2p_blockfilters (MarcoFalke)

### Miscellaneous
- #20861 BIP 350: Implement Bech32m and use it for v1+ segwit addresses (sipa)
- #22002 *Fix crash when parsing command line with -noincludeconf=0 (MarcoFalke)
- #21111 *Improve OpenRC initscript (parazyd)
- #22072 *Add reindex=auto flag to automatically reindex corrupt data (AaronDewes)
- n/a *Store mempool.dat in Bitcoin Core-compatible format (luke-jr)
- n/a *Bugfix: LoadMempoolKnots014: Don't enforce a 32 MiB limit on entire saved mempool (luke-jr)

### Documentation
- #21384 add signet to bitcoin.conf documentation (jonatack)
- #21342 Remove outdated comment (hebasto)

Credits
=======

Thanks to everyone who directly contributed to this release:

- Aaron Clauson
- Aaron Dewes
- Adrian-Stefan Mares
- Amiti Uttarwar
- Andrew Chow
- Andrew Poelstra
- Anthony Towns
- Bastien Teinturier
- benthecarman
- Bruno Garcia
- Christian Decker
- danben
- Dhruv Mehta
- eilx2
- Fabian Jahr
- fanquake
- Gloria Zhao
- Hennadii Stepanov
- Jarol Rodriguez
- Jon Atack
- kiminuo
- Klement Tan
- Kristaps Kaupe
- Luke Dashjr
- Maayan Keshet
- MarcoFalke
- Martin Ankerl
- Martin Zumsande
- parazyd
- Pieter Wuille
- practicalswift
- prayank23
- R E Broadley
- randymcmillan
- S3RK
- Samuel Dobson
- Sebastian Falbesoner
- Sjors Provoost
- Suhas Daftuar
- Vasil Dimov
- W. J. van der Laan

As well as to everyone that helped with translations on
[Transifex](https://www.transifex.com/bitcoin/bitcoin/).
