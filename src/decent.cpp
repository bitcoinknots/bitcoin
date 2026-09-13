// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <decent.h>

#include <chain.h>
#include <coins.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <script/script.h>
#include <tinyformat.h>

#include <algorithm>
#include <limits>
#include <map>
#include <ranges>
#include <set>

bool IsDecentActive(int height, const Consensus::Params& params)
{
    return params.decent_activation_height != std::numeric_limits<int>::max() &&
           height >= params.decent_activation_height;
}

CScript DecentEscrowScript(const CScript& payee, const std::vector<CPubKey>& committee)
{
    CScript script;
    script << std::vector<unsigned char>(payee.begin(), payee.end()) << OP_DROP << OP_2;
    for (const CPubKey& key : committee) script << ToByteVector(key);
    script << OP_3 << OP_CHECKMULTISIG;
    return script;
}

std::optional<DecentEscrow> ParseDecentEscrow(const CScript& script)
{
    CScript::const_iterator pc{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(pc, opcode, data) || data.empty() || data.size() > MAX_DECENT_PAYEE_SIZE) return std::nullopt;

    DecentEscrow escrow;
    escrow.payee = CScript(data.begin(), data.end());

    // Read the three committee keys back out and rebuild, so any non-canonical
    // encoding is rejected.
    std::vector<CPubKey> committee;
    // Skip OP_DROP OP_2
    if (!script.GetOp(pc, opcode, data) || opcode != OP_DROP) return std::nullopt;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_2) return std::nullopt;
    for (int i = 0; i < 3; ++i) {
        if (!script.GetOp(pc, opcode, data) || data.size() != CPubKey::COMPRESSED_SIZE) return std::nullopt;
        CPubKey key{data};
        if (!key.IsFullyValid()) return std::nullopt;
        committee.push_back(key);
    }
    escrow.committee = committee;
    if (DecentEscrowScript(escrow.payee, committee) != script) return std::nullopt;
    return escrow;
}

CScript DecentClaimWitnessScript(const std::vector<CPubKey>& committee, const Consensus::Params& params)
{
    CScript script;
    script << int64_t{params.decent_claim_maturity} << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_2;
    for (const CPubKey& key : committee) script << ToByteVector(key);
    script << OP_3 << OP_CHECKMULTISIG;
    return script;
}

CScript DecentClaimScript(const std::vector<CPubKey>& committee, const Consensus::Params& params)
{
    const CScript witness_script{DecentClaimWitnessScript(committee, params)};
    std::vector<unsigned char> hash(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(witness_script.data(), witness_script.size()).Finalize(hash.data());
    return CScript() << OP_0 << hash;
}

std::vector<CPubKey> ParseDecentVote(const CTransaction& tx)
{
    for (const CTxOut& out : tx.vout) {
        const CScript& spk{out.scriptPubKey};
        if (spk.empty() || spk[0] != OP_RETURN) continue;

        CScript::const_iterator pc{spk.begin() + 1};
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!spk.GetOp(pc, opcode, data)) continue;
        if (pc != spk.end()) continue; // exactly one push, nothing else in the script

        if (data.size() <= DECENT_VOTE_TAG.size()) continue;
        if (!std::ranges::equal(std::span{data}.first(DECENT_VOTE_TAG.size()), DECENT_VOTE_TAG)) continue;

        const size_t candidate_bytes{data.size() - DECENT_VOTE_TAG.size()};
        if (candidate_bytes == 0 || candidate_bytes % CPubKey::COMPRESSED_SIZE != 0) continue;
        const size_t n{candidate_bytes / CPubKey::COMPRESSED_SIZE};
        if (n < 1 || n > 2) continue; // not a well-formed vote; try the next output

        std::vector<CPubKey> candidates;
        bool all_valid{true};
        for (size_t i = 0; i < n && all_valid; ++i) {
            const size_t off{DECENT_VOTE_TAG.size() + i * CPubKey::COMPRESSED_SIZE};
            CPubKey key{std::span{data}.subspan(off, CPubKey::COMPRESSED_SIZE)};
            if (!key.IsFullyValid()) { all_valid = false; break; }
            if (std::ranges::find(candidates, key) == candidates.end()) candidates.push_back(key); // dedupe
        }
        if (!all_valid || candidates.empty()) continue;
        return candidates; // the first well-formed vote output counts
    }
    return {};
}

static std::vector<CPubKey> ParseAuthority(const std::vector<std::vector<unsigned char>>& raw)
{
    std::vector<CPubKey> keys;
    for (const auto& bytes : raw) {
        CPubKey key{bytes};
        if (key.IsFullyValid()) keys.push_back(key);
    }
    return keys;
}

//! Tally one complete term's votes and return its three winners, or empty when
//! the term did not name three distinct pubkeys.
static std::vector<CPubKey> ElectFromTerm(const CBlockIndex* pindex_prev, node::BlockManager& blockman,
                                          int term_start, int term_end)
{
    std::map<std::vector<unsigned char>, int> tally;
    for (int height = term_start; height < term_end; ++height) {
        const CBlockIndex* index{pindex_prev->GetAncestor(height)};
        if (!index) continue;
        CBlock block;
        if (!blockman.ReadBlock(block, *index) || block.vtx.empty()) continue;
        // Votes are node operators' transactions, never the block's own
        // coinbase: skip vtx[0] so a party with a hashpower majority cannot
        // also hand itself a majority of votes. See decent.h.
        for (size_t i = 1; i < block.vtx.size(); ++i) {
            for (const CPubKey& candidate : ParseDecentVote(*block.vtx[i])) {
                ++tally[std::vector<unsigned char>(candidate.begin(), candidate.end())];
            }
        }
    }

    // Rank by votes, breaking ties by pubkey so every node elects the same three.
    std::vector<std::pair<std::vector<unsigned char>, int>> ranked{tally.begin(), tally.end()};
    std::ranges::sort(ranked, [](const auto& a, const auto& b) {
        return a.second != b.second ? a.second > b.second : a.first < b.first;
    });
    if (ranked.size() < 3) return {};

    std::vector<CPubKey> winners;
    for (int i = 0; i < 3; ++i) winners.emplace_back(ranked[i].first);
    return winners;
}

std::vector<CPubKey> ComputeDecentAuthority(const CBlockIndex* pindex_prev, node::BlockManager& blockman, const Consensus::Params& params)
{
    const int height{pindex_prev ? pindex_prev->nHeight + 1 : 0};
    if (!IsDecentActive(height, params)) return {};

    const int term{(height - params.decent_activation_height) / params.decent_term_length};
    std::vector<CPubKey> authority{ParseAuthority(params.decent_bootstrap_authority)};

    for (int t = 1; t <= term; ++t) {
        const int term_start{params.decent_activation_height + (t - 1) * params.decent_term_length};
        const auto elected{ElectFromTerm(pindex_prev, blockman, term_start, term_start + params.decent_term_length)};
        if (elected.size() == 3) authority = elected;
    }
    return authority;
}

bool CheckDecentCoinbase(const CTransaction& coinbase, const std::vector<CPubKey>& committee, const Consensus::Params& params, BlockValidationState& state)
{
    if (committee.size() != 3) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-decent-no-authority",
                             "no three-key authority is established to escrow this coinbase");
    }
    for (size_t i = 0; i < coinbase.vout.size(); ++i) {
        // Zero-value outputs, such as the witness commitment and any vote, carry
        // no coins to escrow.
        if (coinbase.vout[i].nValue == 0) continue;
        const auto escrow{ParseDecentEscrow(coinbase.vout[i].scriptPubKey)};
        if (!escrow || escrow->committee != committee) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-decent-coinbase",
                                 strprintf("coinbase output %u is not escrowed for the current authority", i));
        }
    }
    return true;
}

bool IsDecentEscrowSpend(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase()) return false;
    for (const CTxIn& in : tx.vin) {
        const Coin& coin{inputs.AccessCoin(in.prevout)};
        if (coin.IsCoinBase() && ParseDecentEscrow(coin.out.scriptPubKey)) return true;
    }
    return false;
}

bool CheckDecentDecision(const CTransaction& tx, const CCoinsViewCache& inputs, const Consensus::Params& params, TxValidationState& state)
{
    std::optional<DecentEscrow> escrow;
    int escrow_inputs{0};
    for (const CTxIn& in : tx.vin) {
        const Coin& coin{inputs.AccessCoin(in.prevout)};
        if (!coin.IsCoinBase()) continue;
        if (auto e{ParseDecentEscrow(coin.out.scriptPubKey)}) {
            ++escrow_inputs;
            escrow = std::move(e);
        }
    }
    if (escrow_inputs == 0) return true; // not a decision

    if (escrow_inputs != 1 || tx.vin.size() != 1 || tx.vout.size() != 1) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-decent-decision-shape",
                             "an escrowed coinbase must be the only input, spent to a single output");
    }
    const CScript& destination{tx.vout[0].scriptPubKey};
    if (destination != escrow->payee && destination != DecentClaimScript(escrow->committee, params)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-decent-destination",
                             "an escrowed coinbase may only be released to its payee or claimed by the authority");
    }
    return true;
}
