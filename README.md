Bitcoin Purity
==============

https://bitcoinpurity.org

Bitcoin Purity is a full node for Bitcoin as **pure money and a payment system**.
It is not a data-storage platform, and it should not grow into a general-purpose
application layer.

This repository is a fork of [Bitcoin Knots](https://github.com/bitcoinknots/bitcoin)
`v29.4.knots20260508`. Consensus rules from BIP110 (Reduced Data / RDTS) are
kept and made **permanent** via a hard fork. There is **no transaction-level
replay protection**: addresses, transaction formats, and sighash remain those
of Bitcoin. The intent is that the legacy chain is eventually abandoned and
Bitcoin Purity is Bitcoin.

Binaries remain `bitcoind`, `bitcoin-qt`, and `bitcoin-cli`. The default data
directory remains `~/.bitcoin`.

What is Bitcoin Purity?
-----------------------

Bitcoin Purity connects to the Bitcoin peer-to-peer network, downloads and
fully validates blocks and transactions, and optionally provides a wallet and
GUI.

Project documents:

- [Versioning](doc/VERSION.md)
- [Vision](doc/purity-vision.md)
- [Consensus changes](doc/purity-consensus.md)
- [Roadmap](doc/roadmap.md)
- [Setup and build](doc/README.md)

Short-term consensus (see [doc/purity-consensus.md](doc/purity-consensus.md)):

1. BIP110/RDTS rules are always on and cannot be disabled.
2. Difficulty uses 24-hour ASERT (`aserti3-1d`), anchored at BIP110 enforcement-chain block 961632. Proof-of-work remains SHA256d.
3. Reorgs deeper than 6 blocks are parked for human review by default (local chain-selection policy, not consensus). Operators may change the threshold with `-parkreorgdepth=<n>` or disable parking with `-parkdeepreorg=0`.
4. Automatic freeze of double-spend coinbases and inputs is specified but **not implemented** yet.

How to run Bitcoin Purity?
--------------------------

See [doc/INSTALL.md](doc/INSTALL.md)

License
-------

Bitcoin Purity is released under the MIT license. See [COPYING](COPYING).

Development Process
-------------------

Development happens in this repository: [saltduck/bitcoinpurity](https://github.com/saltduck/bitcoinpurity).
See [CONTRIBUTING.md](CONTRIBUTING.md).

Testing
-------

Unit tests: `ctest` (see [src/test/README.md](/src/test/README.md)).

Functional tests: `build/test/functional/test_runner.py` (see [test/README.md](/test/README.md)).
