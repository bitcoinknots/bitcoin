Proof of Decentralization
=========================

This is [Bitcoin Knots](https://github.com/bitcoinknots/bitcoin) with a proposed
consensus change, **Proof of Decentralization**, added for review.

Bitcoin's block reward today belongs to whoever holds the hashpower. Proof of
Decentralization keeps proof of work for ordering blocks but places the issuance
of new coins under an authority of three keys that miners elect and replace each
term. Every coinbase is escrowed to that authority, which can release the reward
to the miner who earned it or claim it, but cannot redirect it to an outsider.

The rules are implemented in full and covered by tests. They are wired onto
mainnet, testnet, testnet4 and signet but **dormant**: the activation height is a
placeholder far in the future, left for a network's operators to set together
with a first authority. A standalone `-decentral` chain runs the rules from
genesis for testing.

How it works
------------

Every coinbase output carrying value must be escrowed:

    <payee scriptPubKey> OP_DROP 2 <k1> <k2> <k3> 3 OP_CHECKMULTISIG

The miner names the payee it intends; the three keys are the authority sitting
when the block is mined. The 2-of-3 multisig is enforced by the ordinary script
interpreter. On top of it, consensus allows a spend of an escrow only to the
named payee (a release) or to the same three keys behind a relative timelock (a
claim). Blocks are never delayed; only the reward waits for a decision.

Miners elect the authority by naming a public key in each block they mine
(`-decentralvote`). Over a term, the three keys named in the most blocks become
the next term's authority.

See [doc/proof-of-decentralization.md](doc/proof-of-decentralization.md) for the
full mechanism, and
[doc/proof-of-decentralization-activation.md](doc/proof-of-decentralization-activation.md)
for what activating it on a live network would require.

Running the test chain
----------------------

    bitcoind -decentral \
        -decentralbootstrap=<pubkey> -decentralbootstrap=<pubkey> -decentralbootstrap=<pubkey>

`getdecentinfo` reports the authority and term, `getpendingcoinbases` lists
rewards awaiting a decision, and `decidecoinbase` signs a release or a claim.

What this changes, honestly
---------------------------

This concentrates the block subsidy in an elected committee. It is a real
centralization of issuance, chosen deliberately: a network adopting it trusts
whoever miners elect to pay honest miners and not to withhold or seize rewards.
Proof of work still decides the order of blocks, and a majority of hashpower can
still reorganise the chain. Proof of Decentralization changes who is paid, not
who writes history. A reviewer should weigh it on exactly those terms.

Everything else is Bitcoin Knots
--------------------------------

Every change is gated on a single consensus flag that only the Proof of
Decentralization rules set. Mainnet, testnet, testnet4, signet and regtest
behave as they do upstream until a real activation height is chosen. Further
information about Bitcoin Knots is in the [doc folder](/doc).

License
-------

Released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.
