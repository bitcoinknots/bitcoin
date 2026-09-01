Bitcoin Purity version 1.0.0rc1
================================

This release adopts the independent versioning convention documented in
[doc/VERSION.md](VERSION.md). It supersedes the legacy build
`29.4.0.purity20260823`.

Source and issues:

  <https://github.com/saltduck/bitcoinpurity>

Notable changes
===============

### Brand

The client name is **Bitcoin Purity**. Binaries and the default data
directory are unchanged (`bitcoind`, `bitcoin-qt`, `~/.bitcoin`).

See [doc/purity-vision.md](purity-vision.md).

### Consensus (implemented in this tree toward the hard fork)

Rules are specified in [doc/purity-consensus.md](purity-consensus.md):

- BIP110/RDTS is always enforced and cannot be disabled.
- Difficulty uses aserti3-1d (24-hour half-life), anchored at BIP110
  enforcement-chain block 961632. Proof-of-work remains SHA256d.
- Reorgs deeper than 6 blocks are parked for manual `unparkblock` or
  `invalidateblock`. This is local chain-selection policy, not consensus;
  operators may override the threshold with `-parkreorgdepth=<n>` or
  disable it with `-parkdeepreorg=0`.

There is no transaction-level replay protection.

### Not in this release

- Automatic freeze of double-spend coinbases and inputs (specified only).
- SEAL-2, removing Taproot/Segwit, post-quantum signatures, 32 MB blocks
  (see [doc/roadmap.md](roadmap.md)).

How to Upgrade
==============

If you are running Bitcoin Core or Knots, shut it down completely, then
install Bitcoin Purity over the same data directory if you intend to follow
the Purity/BIP110 enforcement chain.

Compatibility
=============

Supported on Linux, macOS 13+, and Windows 10+.
