# Proof of Decentralization

Proof of Decentralization keeps Bitcoin's proof of work but changes who controls
newly minted coins. Blocks are mined and weighted exactly as today. From the
activation height, every coinbase is escrowed to an authority of three public
keys that miners elect, and that authority decides whether each block reward
reaches the miner who earned it.

It is implemented as its own rules, gated behind an activation height. On the
public networks that height is a far-future placeholder, so the rules are
present in the code but dormant; a network's operators choose a real height and
a first authority to turn them on. A standalone `-decentral` chain runs the
rules from genesis for testing.

## What a coinbase looks like

Every coinbase output carrying value must be escrowed:

    <payee scriptPubKey> OP_DROP 2 <k1> <k2> <k3> 3 OP_CHECKMULTISIG

The miner still names the payee it intends. The three keys are the authority
sitting when the block is mined. The two-of-three multisig is enforced by the
ordinary script interpreter; there is no new signature machinery.

On top of the multisig, consensus restricts where the coins may go. A
transaction spending an escrow must spend nothing else, create exactly one
output, and pay either:

* **the payee named in the escrow** (a release), or
* **the same three keys behind a relative timelock** of `decent_claim_maturity`
  blocks (a claim), as `wsh(and_v(v:older(N),multi(2,k1,k2,k3)))`.

So the authority can honour the miner or take the reward for itself, but cannot
send it to an outsider, and no one outside the authority can move it at all. A
block whose coinbase pays out directly is invalid.

Blocks are never held up. Mining, transaction confirmation and chain selection
proceed as normal; only the block reward waits for a decision, and ordinary
coinbase maturity still applies before a decision can confirm.

## Electing the authority

Voting is a wallet operation, not a mining one, and a vote cast in a block's own
coinbase is never counted (see `castdecentvote`). An ordinary, non-coinbase
transaction carries the vote:

    OP_RETURN <"DEC1" || pubkey_1 [|| pubkey_2]>

naming 1 or 2 candidates (capped below 3 by the fixed 80-byte OP_RETURN policy
ceiling). Over a term of `decent_term_length` blocks, the pubkeys with the most
points across all such transactions become the next term's authority, ties
broken by pubkey. If a term does not name three distinct pubkeys, the sitting
authority carries over.

Excluding coinbase votes from the tally is what stops a hashpower majority from
also handing itself a majority of votes: mining a block and voting for the
authority are unrelated actions, costing unrelated resources.

The authority that mints a coinbase is the one that can settle it, for the life
of that coinbase. An election changes who mints and settles future coinbases,
not who settles past ones.

## Running a node

    bitcoind -decentral \
        -decentralbootstrap=<pubkey> -decentralbootstrap=<pubkey> -decentralbootstrap=<pubkey>

`getdecentinfo` reports whether the rules are active, the activation height, the
term, and the current authority. `getpendingcoinbases` lists escrowed coinbases
awaiting a decision.

## Acting as the authority

`decidecoinbase <txid> <vout> release|claim [privkey, privkey]` builds and signs
a decision with two of the authority's keys and returns the transaction; a claim
also returns an output descriptor for the locked coins. Broadcast it with
`sendrawtransaction`.

Passing private keys to a node over RPC exposes them to that node. In practice
each authority member would sign on their own machine and combine the two
signatures; the single-call form here is for testing and for a member who holds
two keys.

## What the authority controls, and what it does not

The authority controls issuance: newly minted coins reach circulation only with
its agreement, and it can divert any block reward to itself. It does not control
which transactions confirm, the order of blocks, or coins already released. It
is a two-of-three committee, elected and replaced by miners each term, so no
single member can act alone and a term-long shift in mining support replaces it.

This concentrates the block subsidy in an elected committee. It is a real
centralization of issuance, chosen deliberately, and it should be weighed as
that: a network adopting it is trusting whoever miners elect to pay honest
miners and not to withhold or seize rewards. Losing all three keys of a sitting
authority freezes the coinbases it minted; the timelock on claims exists so a
claim cannot be spent instantly, giving the network time to react to a
compromised committee.

## Activation on an existing network

`doc/proof-of-decentralization-activation.md` sets out what turning this on for
a chain with value would require: a flag day, grandfathering so pre-activation
history still validates, and a first authority. The public-network activation
height in this build is a placeholder far in the future; it is the operators'
decision to set a real one.

## Tests

`test/functional/feature_proofofdecentralization.py` covers escrowed coinbases,
release, claim, the ban on redirecting or forging a decision, rejection of a
direct-pay coinbase, and an election that rotates the authority.
