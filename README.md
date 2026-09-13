Coinbase Curfew
===============

A fork of [Bitcoin Knots](https://github.com/bitcoinknots/bitcoin) that extends
how long a coinbase output must wait before it can be spent. From a configured
height, spending any coinbase requires additional confirmations beyond
ordinary 100-block maturity. Proof of work and block validity are otherwise
unchanged; miners are paid the same amount, just later.

Why
---

Coinbase maturity already exists to stop a reorg from unwinding an already-spent
block reward. This fork asks a different question: what if the delay were long
enough to matter economically, not just to prevent double-spends? A miner who
mines only to immediately sell the reward behaves differently than one willing
to wait months to receive it. A long curfew doesn't stop anyone from being paid
— it just separates miners willing to hold from miners who are not.

How it works
------------

Two consensus parameters control the change:

- `curfew_height` — the height from which the rule applies. Defaults to unset
  ("never") on every network.
- `curfew_depth` — additional confirmations required beyond the ordinary
  100-block `COINBASE_MATURITY`, defaulting to 25,200 (roughly six months at
  ten minutes per block).

Once `curfew_height` is reached, spending any coinbase output requires
`COINBASE_MATURITY + curfew_depth` confirmations, checked both in mempool
acceptance and in block validation, so a curfew-violating spend cannot sit in
the mempool waiting to be mined, and cannot be smuggled into a block either.

Exercised on regtest for testing:

    bitcoind -regtest -curfewheight=<height> -curfewdepth=<n>

Activating this on a live network — choosing a real `curfew_height` — is a
separate, deliberate decision left to that network's operators. This build does
not set one for mainnet, testnet, testnet4, or signet.

Testing
-------

`test/functional/feature_coinbase_curfew.py` mines across the activation
height, confirms a coinbase mature under ordinary rules is still locked, checks
the one-block-short boundary, and confirms the same coinbase spends normally
once the full curfew depth has passed.

License
-------

MIT. See [COPYING](COPYING).
