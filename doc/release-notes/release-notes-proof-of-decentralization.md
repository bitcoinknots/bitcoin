Proof of Decentralization
=========================

This build adds Proof of Decentralization, a proposed consensus change under
which proof of work continues to order blocks but the issuance of new coins is
placed under an authority of three keys that miners elect each term.

From an activation height, every coinbase output carrying value must be escrowed
to the current authority as a 2-of-3 multisig committing to the miner's intended
payee. A transaction spending an escrow may only release it to that payee or
claim it for the authority behind a relative timelock; it cannot be redirected.
Miners elect the authority by naming a public key in each coinbase; the three
keys named in the most blocks over a term form the next term's authority.

The rules are scheduled on mainnet, testnet, testnet4 and signet at a
placeholder height far in the future, so they are present but dormant until a
network's operators choose a real activation height and a first authority.
Regtest is unaffected. A standalone `-decentral` chain runs the rules from
genesis.

New options
-----------

- `-decentral` selects the Proof of Decentralization test chain.
- `-decentralbootstrap=<pubkey>` sets a first-term authority key (three expected)
  on that chain, with `-decentraltermlength` and `-decentralclaimmaturity`.
- `-decentralvote=<pubkey>` casts this node's vote for the next authority in
  each block it mines.

New RPCs
--------

- `getdecentinfo` reports whether the rules are active, the activation height,
  the term, and the current authority.
- `getpendingcoinbases` lists escrowed coinbase outputs awaiting a decision.
- `decidecoinbase` signs a release or claim of an escrowed coinbase with two
  authority keys.
- `getblockchaininfo` reports `decent_activation_height` where scheduled.
