# Activating Proof of Decentralization on an existing network

The Proof of Decentralization rules (see `doc/proof-of-decentralization.md`) are
present on mainnet, testnet, testnet4 and signet in this build, but dormant: the
activation height is a placeholder far in the future. This document describes
what turning them on for a live network would require, so the change can be
reviewed as a proposal rather than a fait accompli.

## What activation needs

1. **A flag day.** A height, chosen far enough ahead that the network can
   upgrade, from which coinbases must be escrowed. Before it, coinbases follow
   today's rules; from it, `CheckDecentCoinbase` applies. This is a restriction
   on what a valid coinbase may look like, so it takes effect as a soft fork:
   blocks from miners who have not upgraded, paying their coinbase out directly,
   are rejected by upgraded nodes.

2. **A first authority.** The rules cannot escrow to an elected authority until
   an election has happened, and the first election cannot happen until there
   are blocks to vote in. A network must therefore ship a bootstrap authority of
   three keys, in force for the first term, chosen openly by whoever operates the
   network. This build leaves it empty on the public networks; it is the
   operators' decision.

3. **Grandfathering.** Coinbases mined before the flag day are ordinary payouts
   and must keep validating. The rules apply only from the activation height, so
   syncing the chain's own history is unaffected.

## Why it is left dormant here

Escrowing every coinbase to an elected committee is a deliberate centralization
of issuance. It is defensible only if a network's participants choose it with
open eyes, having agreed on who the first authority is and on the trade-off that
miners are then paid at the committee's discretion. That is a governance
decision, not one to encode as a live flag day in software other people run.

So the mechanism is complete and reviewable, and the switch is left for the
network's operators to set. Setting `decent_activation_height` to a real height,
and `decent_bootstrap_authority` to three agreed keys, is the deliberate act
that turns it on.
