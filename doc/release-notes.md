Bitcoin Knots version 29.4.2.knots20260508 is now available from:

  <https://bitcoinknots.org/files/29.x/29.4.2.knots20260508/>

This release includes further mitigation of the ongoing attack on the network.
[Please read below](#attack-mitigation) for important informed consent on this and upcoming planned
changes.

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

If your node is already pruned past September 21 when you upgrade, your node
may need to re-sync the blockchain from scratch. You will be asked at startup
if this is necessary.

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

Due to attacks from apathetic BLAKE2b incumbents looking to exploit Bitcoin for
profit, the community has decided to extend the current (since 2009) 16-hour
(100 blocks) maturity lock time on newly mined bitcoins up to 350 days, and
possibly make it contingent on actually mining (the attackers are blind hashing
instead of mining).

Because this has the potential for negative side-effects and not been discussed
more broadly (only within the active #strategic chat), this release of Bitcoin
Knots deploys only a 45-day maturity time, but nothing more. If consensus is
reached to extend it further, or withhold payment to attackers, a future update
will be needed. However, miners and hashers are now on notice that these
options are being considered and they may need to wait much longer or (if not
mining with their own node) never be paid at all. Users should upgrade to this
new version as soon as possible, and plan for updates around mid-October
and 2027 August.

If you are "mining" without running DATUM Gateway yourself, you are NOT
actually mining, and are in fact attacking the network. You should expect to
_never_ get paid any rewards for that going forward. If you wish to mine
properly, set up your own DATUM Gateway and use it for mining. There is
volunteer tech support available on the Knots Discord ⁠#support channel. Or for
basic instructions, see:

  <https://bitcoinknots.org/learn/mining>

Please join and participate in the #⁠⁠strategic Discord channel if you hold any opinion or wish to discuss suggestions/plans on this matter.

  <https://bitcoinknots.org/social/discord>

Notable changes
===============

- SHA256d difficulty and BLAKE2b difficulty are entirely different units and
  cannot be compared or converted. To address this, the "difficulty" field has
  been removed where applicable (SHA256d block information retains it), and
  the `getdifficulty` RPC method has been removed. A new "difficulty_blake2b"
  field has been added for BLAKE2b blocks, as well as in the result for
  `getblockchaininfo`. knots#420

### Validation

- knots#419 T.Softfork: Long coinbase maturity (part 1 of 3)

### Net

- #30951 net: Support -listen with -v2onlyclearnet properly
- #35766 p2p: Assume v2transport for addresses from seeds
- seeds: update fixed dns seeds for mainnet and testnet4

### RPC

- knots#420 Bugfix: RPC: Replace SHA256d "difficulty" with "difficulty_blake2b"

### Misc

- knots#365 test: Skip the completion-file comparison in pull request CI

Credits
=======

Thanks to everyone who directly contributed to this release:

- Chris Guida
- Luke Dashjr
- Martin Zumsande
- stratospher

As well as to the rest of the community for your patience and support as we
mitigate the biggest attack on Bitcoin in history.
