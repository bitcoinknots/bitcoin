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

---

Contents
--------

- [Why](#why)
- [The escrow output](#the-escrow-output)
- [Spending an escrow: release and claim](#spending-an-escrow-release-and-claim)
- [Electing the authority](#electing-the-authority)
- [How a node computes the authority](#how-a-node-computes-the-authority)
- [Consensus rules in full](#consensus-rules-in-full)
- [Activation and dormancy](#activation-and-dormancy)
- [Running the test chain](#running-the-test-chain)
- [RPCs](#rpcs)
- [Where the code lives](#where-the-code-lives)
- [What this changes, honestly](#what-this-changes-honestly)
- [Everything else is Bitcoin Knots](#everything-else-is-bitcoin-knots)

Why
---

Since August, when most of the former hashpower left the network and began
promoting a competing chain, one structural fact has been hard to ignore: the
block subsidy follows hashpower and nothing else. A miner mining only to collect
the reward and sell it is paid exactly like one invested in the network, and
nodes cannot tell them apart, because a valid block is a valid block. The people
who run nodes and enforce the rules have no say in who is paid to extend the
chain.

Proof of Decentralization keeps proof of work but adds that say. Blocks are
still found by hashing and the heaviest chain still wins; what changes is that
the newly minted subsidy is escrowed rather than paid out, and released by an
authority that miners elect. The authority can pay an honest miner or withhold a
reward it judges was earned by a bad actor. It changes who is paid, not who
writes history.

The escrow output
-----------------

From the activation height, every coinbase output that carries value must be a
Proof of Decentralization escrow. The escrow is a bare `OP_CHECKMULTISIG`
script that both names the payee the miner intended and locks the coins to the
three-key authority sitting when the block was mined:

    <payee scriptPubKey> OP_DROP OP_2 <k1> <k2> <k3> OP_3 OP_CHECKMULTISIG

- `<payee scriptPubKey>` is pushed and immediately dropped. It is data, not
  executed; it records where the miner asked the reward to go and lets consensus
  read the intended payee straight from the output.
- `OP_2 <k1> <k2> <k3> OP_3 OP_CHECKMULTISIG` is an ordinary 2-of-3 multisig of
  the current authority's compressed public keys, in the canonical order the
  election produced.

Outputs carrying no value, such as the witness commitment and any vote (below),
are exempt. The payee script is capped at 80 bytes, enough for every standard
address type.

Consensus validates the coinbase against the authority in force at that height:
each value output must parse as this exact template, with the three keys equal
to the elected committee. A coinbase that pays out directly, or escrows to the
wrong keys, makes the block invalid (`bad-decent-coinbase`).

Spending an escrow: release and claim
-------------------------------------

The 2-of-3 multisig is enforced by the ordinary script interpreter: two of the
three authority keys must sign, exactly as for any multisig, with no new
signature machinery. On top of that, consensus restricts *where* those two
signers may send the coins. A transaction that spends an escrow must:

1. spend that escrow as its only input, and
2. create exactly one output, paying either
   - the **payee** named in the escrow (a *release*), or
   - the authority's **claim address** (a *claim*).

Any other shape or destination is rejected (`bad-decent-decision-shape`,
`bad-decent-destination`). So the committee can honour the miner or take the
reward, but cannot redirect it to a third party, and no one outside the
committee can move it at all.

A claim does not hand the committee spendable coins immediately. The claim
address is a P2WSH output whose witness script locks the coins for
`decent_claim_maturity` blocks after the claim confirms:

    <maturity> OP_CHECKSEQUENCEVERIFY OP_DROP OP_2 <k1> <k2> <k3> OP_3 OP_CHECKMULTISIG

which is the miniscript `wsh(and_v(v:older(N),multi(2,k1,k2,k3)))`. The relative
timelock exists so a claim cannot be swept instantly, giving the network time to
react to a committee that misbehaves or whose keys are compromised.

Blocks are never delayed by any of this. Mining, relay, transaction
confirmation and chain selection all proceed normally; only the block reward
waits for a decision, and ordinary 100-block coinbase maturity still applies
before a decision can confirm.

The authority that mints a coinbase is the one that can settle it, for the life
of that coinbase, because its keys are baked into the escrow at mint time. An
election changes who mints and settles future coinbases, not who settles past
ones.

Electing the authority
----------------------

The authority is chosen by node operators, not by miners. Mining a block and
voting for the authority are deliberately unrelated actions: a vote is an
ordinary, fee-paying transaction cast from a wallet with `castdecentvote`, and a
vote embedded in a block's own coinbase is never counted, no matter how it got
there. This is the direct fix for the objection raised on this proposal's PR: a
party with a hashpower majority must not thereby also be able to hand itself a
majority of votes. Deciding who governs issuance now costs a spendable coin and
a transaction fee, a different and much cheaper-to-verify resource than mining
hardware, and one hashpower does not by itself confer.

A vote transaction carries a single output:

    OP_RETURN <"DEC1" || pubkey_1 [|| pubkey_2]>

naming 1 or 2 candidate public keys (capped below 3 because 3 compressed
pubkeys plus the tag is 103 bytes, past this build's fixed 80-byte OP_RETURN
policy ceiling, which cannot be raised past that limit). Each named candidate
receives one point (approval voting: naming two candidates costs nothing extra
and doesn't dilute support for either one). Over a term of `decent_term_length`
blocks, the pubkeys with the most points across every non-coinbase vote
transaction become the next term's authority. Ties are broken by byte order of
the pubkey, so every node reaches the same result. If a term does not name at
least three distinct keys, the sitting authority carries over to the next term.

The first term has no prior term to elect from, so a network ships a **bootstrap
authority** of three keys, in force until the first election completes.

How a node computes the authority
---------------------------------

The authority in force for a block at height *h* is deterministic from the chain
alone. Let *A* be the activation height and *L* the term length. The term index
is `t = (h - A) / L`. For `t == 0` the authority is the bootstrap set. For
`t > 0` the node tallies the votes cast in term `t-1` (the blocks at heights
`[A + (t-1)*L, A + t*L)`), takes the top three, and falls back to the previous
term's authority if the election named fewer than three.

Because this reads the coinbases of the previous term, a node walks its own
block index and reads those blocks to compute the tally. Every node with the
same chain computes the same authority, so it is a pure function of history and
needs no external input.

Consensus rules in full
-----------------------

With the rules active at height *h*, a block is valid only if, in addition to
all existing Bitcoin Knots rules:

1. **Coinbase escrow.** Every coinbase output with `nValue > 0` parses as the
   escrow template above, with the three keys equal to the authority computed
   for *h*. (`bad-decent-coinbase`; `bad-decent-no-authority` if no committee is
   established.)
2. **Decision shape.** A transaction spending any escrow output spends exactly
   that one input and creates exactly one output. (`bad-decent-decision-shape`.)
3. **Decision destination.** That single output pays either the escrow's named
   payee or the claim P2WSH derived from the escrow's own three keys.
   (`bad-decent-destination`.)
4. **Decision signature.** The 2-of-3 multisig is satisfied, checked by the
   script interpreter in the ordinary way (no rule added here; a bad signature
   fails as any multisig would).

Rules 2 and 3 are additional restrictions on top of an otherwise valid script
spend: they tighten what is allowed, they do not relax script verification. This
matters for review, because it means the change cannot make a previously invalid
spend valid.

Activation and dormancy
-----------------------

The rules are gated on `decent_activation_height`. On mainnet, testnet, testnet4
and signet it defaults to a placeholder far in the future
(`DEFAULT_DECENT_ACTIVATION_HEIGHT`, roughly two centuries out at ten-minute
blocks), so the rules are compiled in but never trigger. Regtest sets it to
"never" so the existing regression suite is unaffected. The `-decentral` test
chain sets it to 0, active from genesis.

Turning the rules on for a real network is two deliberate changes: a real
`decent_activation_height`, and a `decent_bootstrap_authority` of three agreed
keys. Both are governance decisions, left to a network's operators;
`doc/proof-of-decentralization-activation.md` covers the flag-day mechanics,
grandfathering of pre-activation history, and the bootstrap requirement.

Running the test chain
----------------------

    bitcoind -decentral \
        -decentralbootstrap=<pubkey> -decentralbootstrap=<pubkey> -decentralbootstrap=<pubkey> \
        -decentraltermlength=<n> -decentralclaimmaturity=<n>

The test chain mines instantly, like regtest, so the escrow, election and claim
paths can be exercised quickly. It uses its own network magic, ports and `dcrt`
address prefix, so it cannot be confused with any other network.

RPCs
----

- `getdecentinfo` — whether the rules are active, the activation height, the term
  length and claim maturity, the current term, and the current authority.
- `getpendingcoinbases [depth]` — escrowed coinbase outputs not yet released or
  claimed, with their payee, amount and maturity.
- `decidecoinbase <txid> <vout> release|claim [privkey,privkey] [fee]` — build
  and sign a release or claim with two authority keys; a claim also returns an
  output descriptor for the locked coins.
- `castdecentvote [pubkey,pubkey]` — broadcast this wallet's vote for the next
  authority, naming 1 or 2 candidates. Requires a funded wallet; costs an
  ordinary transaction fee.
- `getblockchaininfo` — reports `decent_activation_height` where scheduled.

Where the code lives
--------------------

- `src/decent.h`, `src/decent.cpp` — the escrow script, the vote parser, the
  authority election, and the coinbase and decision checks.
- `src/consensus/params.h` — the activation height, term length, claim maturity
  and bootstrap authority parameters.
- `src/kernel/chainparams.cpp` — the `-decentral` chain and the dormant wiring
  on the public networks.
- `src/validation.cpp` — the coinbase and decision checks in block connection
  and mempool acceptance.
- `src/node/miner.cpp` — escrowing the coinbase to the sitting authority.
- `src/wallet/rpc/spend.cpp` — `castdecentvote`, the wallet vote transaction.
- `src/rpc/mining.cpp` — the authority RPCs.

`git grep decent_` reaches every behavioural change.

What this changes, honestly
---------------------------

This concentrates the block subsidy in an elected committee. It is a real
centralization of issuance, chosen deliberately: a network adopting it trusts
whoever miners elect to pay honest miners and not to withhold or seize rewards.
It does not identify or authenticate miners and makes no claim to detect
impersonation; it is a subsidy gate whose judgement is made by the elected
authority, in the open, and recorded permanently on chain. Proof of work still
decides the order of blocks, and a majority of hashpower can still reorganise
the chain. A reviewer should weigh it on exactly those terms.

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
