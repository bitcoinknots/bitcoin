Bitcoin Knots version 29.4.1.knots20260508 is now available from:

  <https://bitcoinknots.org/files/29.x/29.4.1.knots20260508/>

This release includes mitigation of the ongoing attack on the network, as well
as a few improvements to spam filters.

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

If your node was old, pruned, and followed invalid blocks, your node may need
to re-sync the blockchain from scratch. You will be asked at startup if this
is necessary.

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

Attack Mitigation
=================

On August 8th, most former miners abandoned Bitcoin en masse and together with
other bad actors have been falsely promoting a new altcoin as "Bitcoin". This
is the biggest attack on the Bitcoin network to date, and brought the network
to a crawl.

Mitigating this attack unfortunately requires a backward-incompatible protocol
change, included in this release. It has been 13 years since the last such
change, and several other security issues had been deferred; where practical,
those have also been fixed at the same time.

These changes are included:
- Fix poison blocks (CVE-2013-2292)
- Fix unintentional fees (CVE-2020-14199)
- Fix block tx count mutation (CVE-2017-12842)
- Fix for block withholding attacks
- Minor changes to BIP110 (Reduced Data Temporary Softfork) activation/expiry
- Temporary 800 kWU block weight limit (approximately 300kB in size)
- BLAKE2b proof-of-work algorithm (mitigates ongoing attack)
- Efficiency improvements for mining hardware
- Future-proofing for merge mined sidechains
- Future-proofing for 40-bit block times

Note that other software, such as third-party wallets, may require upgrades to
remain compatible.

If you intend to sell, gift, or spend fake “bitcoins” on the new altcoin
launched by former miners, you should ensure your wallet supports the new
SIGHASH_UNIFIED signature format and re-send your bitcoins to yourself using
it first (the usual cautions on waiting for the transaction to confirm are
applicable).

For more information, please visit:

  <https://bitcoinknots.org/learn/2026-blake2b>

Notable changes
===============

The `rejecttokens` spam filter has been enabled by default, and now also
detects Counterparty transactions.

### Validation

- knots#357 Consensus: Unified opt-in sighash for all transaction types
- knots#358 Consensus: Activate RDTS at the PoW-change hardfork (flag day)
- knots#359 Hardfork: New BLAKE2b proof-of-work algorithm
- knots#360 validation: check the block index after InvalidateBlock repairs it
- HARDFORK: chainparams: Add activation parameters for BLAKE2b hardfork (mainnet & testnet4)
- Add mainnet checkpoints for blocks 961,632 (first BIP110) and 961,639 (last SHA256d)

### Net

- knots#368 p2p: Prefer NODE_BLAKE2B peers instead of NODE_REDUCED_DATA
- knots#375 net: add Léo Haf testnet4 seed

### Policy

- knots#349 policy: reject Counterparty messages under -rejecttokens
- knots#354 defaults: Enable rejecttokens by default

### GUI

- knots#377 qt: Fix MSVC C4305 in MempoolStats::drawChart

### RPC

- knots#363 rpc: expose v2 header fields in blockheaderToJSON

### Misc

- knots#362 Remove the RDTS consent requirement

Credits
=======

Thanks to everyone who directly contributed to this release:

- AcesHigh70
- Bill Cox
- Chris Guida
- Christian Heimes
- CodesInChaos
- Frank Denis
- Hodlinator
- Jason A. Donenfeld
- Jason Sopko
- JP Aumasson
- Kai Köhne
- Kyle Santiago
- Léo Haf
- Lőrinc
- Luke Dashjr
- Mangix
- mjvk
- Pádraig Brady
- Philip D'Ath
- Samuel Neves

As well as to the rest of the community for your patience and support as we
mitigate the biggest attack on Bitcoin in history.
