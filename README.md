Loyalty Tax
===========

A fork of [Bitcoin Knots](https://github.com/bitcoinknots/bitcoin) that
requires every coinbase, from a configured height, to pay a fixed share of its
reward to a network treasury. A coinbase that does not also declare loyalty is
not merely taxed — it forfeits the entire block reward to the treasury. Proof
of work and block validity are otherwise unchanged.

Why
---

A subsidy paid unconditionally rewards a miner exactly the same whether or not
they have any stake in the network's future. This fork ties keeping the reward
to declaring, on-chain, an intention to keep mining faithfully — and prices
silence (or open defection) at the cost of the entire block.

How it works
------------

Three consensus parameters control the change:

- `loyalty_height` — the height from which the rule applies. Defaults to
  unset ("never") on every network.
- `loyalty_tax_bps` — the tax rate, in basis points out of 10,000. Defaults to
  1000 (10%).
- `loyalty_treasury_script` — the fixed output script the tax (or the whole
  confiscated reward) is paid to.

From `loyalty_height`, a coinbase is checked against two possibilities:

- **Signaled**: if the coinbase carries a specific `OP_RETURN` output pushing
  the four bytes `LOY1`, it need only pay `loyalty_tax_bps` of the total
  reward (subsidy + fees) to the treasury script. It may do whatever it likes
  with the rest.
- **Unsignaled**: if that marker is absent, the entire reward must be paid to
  the treasury. The miner keeps nothing.

A block that pays the treasury less than what its signaling status requires is
rejected (`bad-loyalty-tax`). The reference miner in this build signals
automatically and pays the tax once `loyalty_height` is reached, so blocks
mined the ordinary way keep working without any special handling by the
operator.

Exercised on regtest for testing:

    bitcoind -regtest -loyaltyheight=<height> -loyaltytaxbps=<bps> -loyaltytreasury=<hex script>

Activating this on a live network is a separate, deliberate choice — a real
`loyalty_height`, a chosen tax rate, and a treasury script agreed on by that
network's operators. This build does not make that choice for mainnet,
testnet, testnet4, or signet.

Testing
-------

`test/functional/feature_loyalty_tax.py` checks normal mining before
activation, confirms the built-in miner produces a compliant coinbase after
activation, and hand-builds blocks to confirm an underpaid signaled block is
rejected, an unsignaled block that keeps any reward is rejected, and an
unsignaled block that fully confiscates its reward is accepted.

License
-------

MIT. See [COPYING](COPYING).
