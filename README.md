Mandatory Sabbatical
=====================

A fork of [Bitcoin Knots](https://github.com/bitcoinknots/bitcoin) that limits
how often the same identity can mine within a rolling window of blocks, from a
configured height. Proof of work and everything else about block validity is
unchanged.

Why
---

Concentrated, continuous block production by the same miner is a visible
symptom of the centralization this fork's sibling proposals are responding to.
This one attacks it directly and literally: an identity that has mined too
many of the recent blocks must sit out until its share of the window drops.

How it works
------------

Three consensus parameters control the change:

- `sabbatical_height` — the height from which the rule applies. Defaults to
  unset ("never") on every network.
- `sabbatical_window` — the size of the rolling window, in blocks. Defaults
  to 10.
- `sabbatical_max` — the most blocks the same identity may hold within that
  window. Defaults to 3.

"Identity" here means the coinbase's primary payout script — `vout[0]`. From
`sabbatical_height`, a new block is rejected (`bad-cb-sabbatical`) if its own
identity's payout script would appear in more than `sabbatical_max` of the
last `sabbatical_window` blocks, this one included. The window rolls forward
with the chain: once enough other blocks have been mined, an identity that was
briefly blocked can mine again.

Exercised on regtest for testing:

    bitcoind -regtest -sabbaticalheight=<height> -sabbaticalwindow=<n> -sabbaticalmax=<n>

**This does not identify miners; it matches an exact output script.** Rotating
payout addresses defeats it completely — an identity is only as sticky as the
address it chooses to reuse. It is a real, working consensus rule against a
literal reading of "the same address, too often," not a robust anti-Sybil or
anti-concentration mechanism.

Activating this on a live network — real values for the three parameters — is
a separate decision left to that network's operators. This build does not make
that choice for mainnet, testnet, testnet4, or signet.

Testing
-------

`test/functional/feature_mandatory_sabbatical.py` covers an identity filling
its allowed share, being rejected for exceeding it, a different identity being
unaffected, and the window rolling forward to allow the first identity back in.

License
-------

MIT. See [COPYING](COPYING).
