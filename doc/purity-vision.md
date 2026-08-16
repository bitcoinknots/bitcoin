# Bitcoin Purity vision

Bitcoin is **money and a payment system**. Bitcoin Purity exists to keep that
definition in consensus, not only in policy.

## What Bitcoin is

- A peer-to-peer electronic cash system.
- A ledger of value transfer, secured by proof-of-work.
- Software that anyone can run to verify their own money.

## What Bitcoin is not

- A general-purpose database or file host.
- An application platform for complex on-chain programs.
- A chain whose rules exist to maximize arbitrary data embedding.

BIP110 / RDTS (Reduced Data) encodes that stance in consensus. Purity makes
those rules **permanent** by hard fork, instead of a one-year temporary
soft fork.

## Relationship to Bitcoin Core and Knots

This node is a fork of Bitcoin Knots `v29.4.knots20260508`, which itself
follows Bitcoin Core with additional policy and the BIP110 implementation.

Purity is not a new asset with a new ticker. It claims the Bitcoin identity:

- Same P2P magic (`f9beb4d9`) and default port (8333).
- Same addresses, transaction serialization, and sighash.
- Same default data directory (`~/.bitcoin`) and binary names (`bitcoind`,
  `bitcoin-qt`, `bitcoin-cli`).
- **No transaction-level replay protection.**

Transactions remain valid on both this chain and a legacy chain that does not
enforce Purity rules. That is intentional. The project waits for the legacy
chain to be abandoned by the community rather than engineering a clean split
into “another coin.”

## Proof-of-work

SHA256d is unchanged. Hashrate defence is operational (difficulty that tracks
real time, and parking of deep reorgs), not an algorithm change.

## Reading next

- [purity-consensus.md](purity-consensus.md) — hard-fork rules.
- [roadmap.md](roadmap.md) — short-term vs later work.
