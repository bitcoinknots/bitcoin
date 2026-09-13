Austerity Mode
==============

A fork of [Bitcoin Knots](https://github.com/bitcoinknots/bitcoin) that removes
the block subsidy from a configured height onward. Miners are paid only by
transaction fees from that point forward. Proof of work, block validity, and
everything else about the chain are unchanged.

Why
---

The block subsidy pays miners regardless of whether they have any stake in the
network's future. A chain secured only by rented hashpower has no claim on that
hashpower's loyalty. Fee revenue already covers security on a network with real
transaction volume; the subsidy is a legacy bootstrap mechanism, not a
permanent entitlement.

This fork proposes cutting it off outright, on a schedule the community sets.

How it works
------------

One consensus parameter, `austerity_height`, controls the change:

- Below it: the subsidy follows the ordinary halving schedule.
- From it: `GetBlockSubsidy` returns zero, and a coinbase may claim only the
  fees collected in its own block. A coinbase that still pays itself the
  subsidy is invalid (`bad-cb-amount`).

The parameter defaults to unset ("never") on every network. It is exercised on
regtest for testing:

    bitcoind -regtest -austerityheight=<height>

Activating it on a live network is a single deliberate choice by that network's
operators: set `austerity_height` in chain params to a real value. This build
does not make that choice for mainnet, testnet, testnet4, or signet.

Testing
-------

`test/functional/feature_austerity.py` mines across the activation height and
confirms the subsidy drops to zero and that a block still claiming it is
rejected by consensus.

License
-------

MIT. See [COPYING](COPYING).
