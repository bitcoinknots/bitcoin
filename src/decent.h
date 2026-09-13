// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DECENT_H
#define BITCOIN_DECENT_H

#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>

#include <array>
#include <optional>
#include <vector>

class CBlock;
class CBlockIndex;
class CCoinsViewCache;
class BlockValidationState;
class TxValidationState;

namespace Consensus {
struct Params;
} // namespace Consensus

namespace node {
class BlockManager;
} // namespace node

/**
 * Proof of Decentralization.
 *
 * Blocks are produced and weighted by proof of work as usual. What changes is
 * who controls newly minted coins. From the activation height, every coinbase
 * output carrying value must pay into an escrow controlled by the network's
 * authority: three public keys, elected by node operators, that rotate every
 * term.
 *
 * The escrow is a bare 2-of-3 multisig of the authority sitting when the block
 * was mined, with the payee the miner intended committed alongside it:
 *
 *     <payee scriptPubKey> OP_DROP 2 <k1> <k2> <k3> 3 OP_CHECKMULTISIG
 *
 * The multisig is enforced by the script interpreter in the ordinary way. On
 * top of that, consensus restricts where the two signers may send the coins: a
 * transaction spending an escrow must spend nothing else, create exactly one
 * output, and pay either the payee named in the escrow (a release) or the same
 * three keys behind a relative timelock of decent_claim_maturity blocks (a
 * claim). The authority can honour the miner or take the reward for itself, but
 * cannot redirect it to an outsider.
 *
 * The authority that mints a coinbase is the one that can settle it, for the
 * life of that coinbase. Elections rotate who mints future coinbases, not who
 * settles past ones.
 *
 * The authority is chosen by vote, and voting is deliberately decoupled from
 * mining. A vote is an ordinary, non-coinbase transaction carrying one output:
 *
 *     OP_RETURN <"DEC1" || pubkey_1 [|| pubkey_2]>
 *
 * naming 1 or 2 distinct candidate pubkeys (see castdecentvote; capped at 2,
 * not 3, because 3 compressed pubkeys plus the tag is 103 bytes, past this
 * build's fixed 80-byte OP_RETURN policy ceiling -- a 2-candidate vote is the
 * most this or any other default-policy node will ever relay). Each named
 * candidate receives one point (approval voting: naming two candidates costs
 * nothing extra and does not dilute a voter's support for either one).
 * Votes cast in a block's own coinbase are never counted, on purpose: the
 * whole point of moving voting out of the coinbase is that a party with a
 * majority of hashpower must not thereby also acquire a majority of votes.
 * Casting a vote costs an ordinary transaction fee — cheap, but not free, and
 * priced in a currency (a spendable UTXO) that hashpower does not by itself
 * confer.
 *
 * Over a term, the three pubkeys with the most points become the next term's
 * authority, ties broken by pubkey so every node computes the same result. If
 * fewer than three distinct pubkeys received any votes, the sitting authority
 * carries over.
 */

//! Largest payee scriptPubKey an escrow may name.
static constexpr size_t MAX_DECENT_PAYEE_SIZE{80};
//! Tag prefixing a coinbase vote payload.
static constexpr std::array<uint8_t, 4> DECENT_VOTE_TAG{'D', 'E', 'C', '1'};

//! What an escrow output records.
struct DecentEscrow {
    CScript payee;
    std::vector<CPubKey> committee;
};

//! Whether the Proof of Decentralization escrow rules apply at the given height.
bool IsDecentActive(int height, const Consensus::Params& params);

//! The escrow script holding a coinbase output for `payee`, spendable 2-of-3 by `committee`.
CScript DecentEscrowScript(const CScript& payee, const std::vector<CPubKey>& committee);

//! The payee and committee recorded by an escrow script, or nullopt if not one.
std::optional<DecentEscrow> ParseDecentEscrow(const CScript& script);

//! The witness script a claim locks coins behind: a timelocked 2-of-3 of the committee.
CScript DecentClaimWitnessScript(const std::vector<CPubKey>& committee, const Consensus::Params& params);

//! Where a claim sends coins: the P2WSH output for DecentClaimWitnessScript.
CScript DecentClaimScript(const std::vector<CPubKey>& committee, const Consensus::Params& params);

//! The 1 or 2 candidate pubkeys named by a well-formed vote transaction,
//! deduplicated, or empty if `tx` does not carry one. Operates on any
//! transaction; callers that must not count coinbase votes (see decent.h)
//! are responsible for excluding coinbases before calling this.
std::vector<CPubKey> ParseDecentVote(const CTransaction& tx);

//! The authority in effect for the block at `pindex_prev`'s child height (see decent.h).
std::vector<CPubKey> ComputeDecentAuthority(const CBlockIndex* pindex_prev, node::BlockManager& blockman, const Consensus::Params& params);

//! Every value-bearing coinbase output must be an escrow for `committee`.
bool CheckDecentCoinbase(const CTransaction& coinbase, const std::vector<CPubKey>& committee, const Consensus::Params& params, BlockValidationState& state);

//! Whether `tx` spends any escrowed coinbase output.
bool IsDecentEscrowSpend(const CTransaction& tx, const CCoinsViewCache& inputs);

/**
 * A transaction spending an escrowed coinbase may only release it to its payee
 * or claim it for the committee. Transactions that spend no escrow pass
 * unchanged. The 2-of-3 signature itself is checked by the script interpreter;
 * this adds only the restriction on the destination.
 */
bool CheckDecentDecision(const CTransaction& tx, const CCoinsViewCache& inputs, const Consensus::Params& params, TxValidationState& state);

#endif // BITCOIN_DECENT_H
