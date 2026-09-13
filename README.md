Pool Blocklist (Solo Salvation)
================================

A fork of [Bitcoin Knots](https://github.com/bitcoinknots/bitcoin) that rejects
blocks whose coinbase pays a listed output script, from a configured height.
Proof of work and everything else about block validity is unchanged.

Why
---

Mining through a centralized pool means routing your hashpower's rewards
through a single operator's payout address, over and over, block after block.
This fork lets a network refuse to accept blocks paying known pool addresses
outright, pushing miners toward solo mining or decentralized pool protocols
that don't share this fingerprint.

How it works
------------

Two consensus parameters control the change:

- `blocklist_height` — the height from which the rule applies. Defaults to
  unset ("never") on every network.
- `blocklisted_scripts` — a list of exact output scripts. Empty by default.

From `blocklist_height`, a block whose coinbase pays any output matching an
entry on the list is rejected (`bad-cb-blocklisted`). Any other coinbase is
unaffected.

Exercised on regtest for testing:

    bitcoind -regtest -blocklistheight=<height> -blocklistscript=<hex script> [-blocklistscript=<hex script> ...]

**This is a byte-exact match on the output script, not an identity check.** A
pool operator can trivially evade it by rotating to a new payout address the
network hasn't listed yet. It functions as a public, on-chain declaration —
"this specific address is unwelcome" — rather than an enforcement mechanism
against pool mining in general. Treat it accordingly: it's a statement with
teeth against a specific known address, not a durable filter.

Activating this on a live network — a real `blocklist_height` and an agreed
list of scripts — is a separate decision left to that network's operators.
This build does not make that choice for mainnet, testnet, testnet4, or
signet.

Testing
-------

`test/functional/feature_pool_blocklist.py` confirms a listed script is
accepted before activation, rejected at and after activation, and that any
other script continues to be accepted.

License
-------

MIT. See [COPYING](COPYING).
