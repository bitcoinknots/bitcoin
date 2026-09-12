// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/sharepool.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/common.h>
#include <hash.h>
#include <pow.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <versionbits.h>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>

namespace sharepool {
namespace {
template <size_t N, typename... T>
uint256 DomainHash(const char (&domain)[N], const T&... values)
{
    HashWriter writer;
    writer.write(AsBytes(Span{domain, N})); // Includes the terminating NUL.
    (writer << ... << values);
    return writer.GetHash();
}

bool LessProof(const uint256& a, const uint256& b)
{
    return UintToArith256(a) < UintToArith256(b);
}

bool CheckOwner(const Envelope& envelope, const Signature& signature)
{
    const XOnlyPubKey key{Span{envelope.owner}};
    return key.IsFullyValid() && key.VerifySchnorr(OwnerHash(envelope), signature);
}

bool CheckEnvelope(const Envelope& envelope, const Consensus::Params& consensus,
                   uint32_t height, const uint256& parent)
{
    return envelope.version == 1 && envelope.genesis == consensus.hashGenesisBlock &&
           envelope.rules == RulesHash() && envelope.height == height &&
           envelope.native_parent == parent && !envelope.pool.IsNull() &&
           IsPayoutScript(envelope.payout_script) && XOnlyPubKey{Span{envelope.owner}}.IsFullyValid();
}

bool IsWitnessOutput(const CTxOut& output)
{
    static constexpr unsigned char prefix[]{OP_RETURN, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    return output.nValue == 0 && output.scriptPubKey.size() == 38 &&
           std::equal(std::begin(prefix), std::end(prefix), output.scriptPubKey.begin());
}

/** Extract one contiguous canonical carrier range; every other output is fixed. */
Manifest ExtractManifest(const CTransaction& coinbase, std::vector<CTxOut>& payouts)
{
    std::vector<unsigned char> bytes;
    size_t cursor{0};
    while (cursor < coinbase.vout.size() && IsPayoutScript(coinbase.vout[cursor].scriptPubKey)) {
        payouts.push_back(coinbase.vout[cursor++]);
    }
    if (payouts.empty()) throw std::ios_base::failure("missing monetary payouts");
    uint16_t count{0};
    for (uint16_t index{0}; cursor < coinbase.vout.size(); ++index, ++cursor) {
        const auto& output = coinbase.vout[cursor];
        const auto& script = output.scriptPubKey;
        if (output.nValue != 0 || script.size() > 83) throw std::ios_base::failure("invalid carrier output");
        auto pc = script.begin();
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!script.GetOp(pc, opcode) || opcode != OP_RETURN || !script.GetOp(pc, opcode, data) ||
            pc != script.end() || data.size() <= 8 || data.size() > 80 ||
            script != (CScript{} << OP_RETURN << data) ||
            !std::equal(data.begin(), data.begin() + 4, "SPN1")) {
            throw std::ios_base::failure("noncanonical manifest carrier");
        }
        const uint16_t stated_index = ReadLE16(data.data() + 4);
        const uint16_t stated_count = ReadLE16(data.data() + 6);
        if (index == 0) count = stated_count;
        if (count == 0 || count > (MAX_MANIFEST + 71) / 72 || stated_count != count ||
            stated_index != index || index >= count || (index + 1 < count && data.size() != 80)) {
            throw std::ios_base::failure("invalid manifest chunk ordering or size");
        }
        if (bytes.size() + data.size() - 8 > MAX_MANIFEST) throw std::ios_base::failure("manifest exceeds byte bound");
        bytes.insert(bytes.end(), data.begin() + 8, data.end());
        if (index + 1 == count) {
            ++cursor;
            break;
        }
    }
    if (bytes.empty() || count != (bytes.size() + 71) / 72) throw std::ios_base::failure("incomplete manifest chunks");
    if (cursor < coinbase.vout.size()) {
        if (cursor + 1 != coinbase.vout.size() || !IsWitnessOutput(coinbase.vout[cursor])) {
            throw std::ios_base::failure("unexpected or misplaced coinbase output");
        }
    }
    return DecodeManifest(bytes);
}
} // namespace

Manifest ParseCoinbaseManifest(const CTransaction& coinbase, std::vector<CTxOut>& payouts)
{
    return ExtractManifest(coinbase, payouts);
}

uint256 RulesHash()
{
    return DomainHash("SharePool/rules/v1", SHARE_BITS, MAX_SHARE_AGE, MAX_SHARES);
}

uint256 EnvelopeHash(const Envelope& envelope) { return DomainHash("SharePool/envelope/v1", envelope); }

uint256 OwnerHash(const Envelope& e)
{
    return DomainHash("SharePool/owner/v1", e.genesis, e.rules, e.height, e.native_parent,
                      e.pool, e.owner, e.payout_script);
}

uint256 StateRoot(const std::vector<StateEntry>& state)
{
    std::vector<uint256> leaves;
    leaves.reserve(state.size());
    for (const auto& entry : state) leaves.push_back(DomainHash("SharePool/state/v1", entry));
    return ComputeMerkleRoot(std::move(leaves));
}

uint256 SharesRoot(const std::vector<Share>& shares)
{
    std::vector<uint256> leaves;
    leaves.reserve(shares.size());
    for (const auto& share : shares) leaves.push_back(DomainHash("SharePool/share/v1", share));
    return ComputeMerkleRoot(std::move(leaves));
}

uint256 PayoutsRoot(const std::vector<CTxOut>& payouts) { return DomainHash("SharePool/payouts/v1", payouts); }

bool IsPayoutScript(Span<const unsigned char> s)
{
    return (s.size() == 25 && s[0] == OP_DUP && s[1] == OP_HASH160 && s[2] == 20 && s[23] == OP_EQUALVERIFY && s[24] == OP_CHECKSIG) ||
           (s.size() == 23 && s[0] == OP_HASH160 && s[1] == 20 && s[22] == OP_EQUAL) ||
           (s.size() == 22 && s[0] == OP_0 && s[1] == 20) ||
           (s.size() == 34 && s[0] == OP_0 && s[1] == 32) ||
           (s.size() == 34 && s[0] == OP_1 && s[1] == 32);
}

std::vector<unsigned char> EncodeManifest(const Manifest& manifest)
{
    std::vector<unsigned char> bytes;
    VectorWriter{bytes, 0} << manifest;
    if (bytes.empty() || bytes.size() > MAX_MANIFEST) throw std::ios_base::failure("manifest byte bound");
    return bytes;
}

Manifest DecodeManifest(Span<const unsigned char> bytes)
{
    if (bytes.empty() || bytes.size() > MAX_MANIFEST) throw std::ios_base::failure("manifest byte bound");
    SpanReader reader{bytes};
    Manifest manifest;
    reader >> manifest;
    const auto canonical = EncodeManifest(manifest);
    if (!reader.empty() || canonical.size() != bytes.size() || !std::equal(canonical.begin(), canonical.end(), bytes.begin())) {
        throw std::ios_base::failure("noncanonical manifest serialization");
    }
    return manifest;
}

std::vector<CTxOut> CarrierOutputs(Span<const unsigned char> manifest)
{
    if (manifest.empty() || manifest.size() > MAX_MANIFEST) throw std::ios_base::failure("manifest byte bound");
    const uint16_t count = (manifest.size() + 71) / 72;
    std::vector<CTxOut> outputs;
    for (uint16_t index{0}; index < count; ++index) {
        std::vector<unsigned char> data{'S', 'P', 'N', '1', 0, 0, 0, 0};
        WriteLE16(data.data() + 4, index);
        WriteLE16(data.data() + 6, count);
        const size_t offset = size_t{index} * 72;
        data.insert(data.end(), manifest.begin() + offset, manifest.begin() + std::min(offset + 72, manifest.size()));
        outputs.emplace_back(0, CScript{} << OP_RETURN << data);
    }
    return outputs;
}

std::vector<CTxOut> CalculatePayouts(const Manifest& manifest, CAmount reward)
{
    if (!MoneyRange(reward) || manifest.shares.size() > MAX_SHARES) throw std::invalid_argument("invalid payout reward or share count");
    std::map<std::vector<unsigned char>, uint32_t> counts;
    for (const auto& share : manifest.shares) ++counts[share.origin.payout_script];
    if (counts.empty()) counts[manifest.current.payout_script] = 1;
    const uint32_t total = manifest.shares.empty() ? 1 : manifest.shares.size();
    struct Allocation { std::vector<unsigned char> script; CAmount amount; uint64_t remainder; };
    std::vector<Allocation> allocations;
    CAmount allocated{0};
    for (const auto& [script, count] : counts) {
        // MAX_MONEY * MAX_SHARES fits uint64_t; no target-work multiplication.
        static_assert(uint64_t{MAX_MONEY} <= std::numeric_limits<uint64_t>::max() / MAX_SHARES);
        const uint64_t numerator = static_cast<uint64_t>(reward) * count;
        const CAmount amount = numerator / total;
        allocations.push_back({script, amount, numerator % total});
        allocated += amount;
    }
    std::sort(allocations.begin(), allocations.end(), [](const auto& a, const auto& b) {
        return a.remainder != b.remainder ? a.remainder > b.remainder : a.script < b.script;
    });
    for (CAmount i{0}; i < reward - allocated; ++i) ++allocations.at(i).amount;
    std::sort(allocations.begin(), allocations.end(), [](const auto& a, const auto& b) { return a.script < b.script; });
    std::vector<CTxOut> outputs;
    for (const auto& allocation : allocations) outputs.emplace_back(allocation.amount, CScript{allocation.script.begin(), allocation.script.end()});
    return outputs;
}

bool CheckShare(const Share& share, const CBlockIndex* previous, uint32_t settlement_time,
                const Consensus::Params& consensus, std::string& error)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (!previous || consensus.SharePoolHeight == std::numeric_limits<int>::max() ||
        int64_t{previous->nHeight} + 1 < consensus.SharePoolHeight) return fail("bad-sharepool-inactive");
    const int64_t height = int64_t{previous->nHeight} + 1;
    const int64_t eligible_min = std::max<int64_t>(consensus.SharePoolHeight, height - MAX_SHARE_AGE);
    const auto& header = share.header;
    const int64_t origin_height = header.m_height;
    if (!header.m_header_v2 || header.m_flags != 0 || !header.m_xor_key.IsNull() || header.m_xor_key_mask_clear_bits != 0 ||
        header.m_txcount == 0 || (header.nVersion & VERSIONBITS_TOP_MASK) != VERSIONBITS_TOP_BITS ||
        origin_height < eligible_min || origin_height > height) return fail("bad-sharepool-proof");
    const auto* ancestor = previous->GetAncestor(origin_height - 1);
    if (!ancestor || header.hashPrevBlock != ancestor->GetBlockHash() ||
        header.nBits != GetNextWorkRequired(ancestor, &header, consensus) ||
        header.GetBlockTime() <= ancestor->GetMedianTimePast() ||
        header.GetBlockTime() > int64_t{settlement_time} + 7200 ||
        !CheckEnvelope(share.origin, consensus, origin_height, ancestor->GetBlockHash()) ||
        header.m_mm_rhs != EnvelopeHash(share.origin) || !CheckOwner(share.origin, share.authorization)) {
        return fail("bad-sharepool-proof");
    }
    if (UintToArith256(header.GetHash()) > arith_uint256{}.SetCompact(SHARE_BITS)) return fail("bad-sharepool-shares");
    error.clear();
    return true;
}

bool CheckActiveBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensus,
                      const CBlockIndex* previous, std::optional<CAmount> expected_reward)
{
    const auto fail = [&](const std::string& reason) { return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-sharepool-" + reason); };
    if (!previous || !block.m_header_v2 || block.m_flags != 0 || !block.m_xor_key.IsNull() ||
        block.m_xor_key_mask_clear_bits != 0 || block.m_txcount == 0 ||
        (block.nVersion & VERSIONBITS_TOP_MASK) != VERSIONBITS_TOP_BITS ||
        block.vtx.empty() || !block.vtx[0]->IsCoinBase()) return fail("manifest");
    const uint32_t height = previous->nHeight + 1;
    if (block.m_height != int64_t{height} || block.hashPrevBlock != previous->GetBlockHash()) return fail("context");
    std::vector<CTxOut> payouts;
    Manifest manifest;
    try { manifest = ExtractManifest(*block.vtx[0], payouts); }
    catch (const std::exception&) { return fail("manifest"); }
    const auto& current = manifest.current;
    if (!CheckEnvelope(current, consensus, height, previous->GetBlockHash()) ||
        block.m_mm_rhs != EnvelopeHash(current)) return fail("context");
    if (!CheckOwner(current, manifest.authorization)) return fail("owner");
    if (height == uint32_t(consensus.SharePoolHeight)) {
        if (manifest.has_parent || !manifest.parent_state.empty()) return fail("parent");
    } else {
        const auto* grandparent = previous->pprev;
        if (!manifest.has_parent || !grandparent ||
            !CheckEnvelope(manifest.parent, consensus, previous->nHeight, grandparent->GetBlockHash()) ||
            EnvelopeHash(manifest.parent) != previous->m_mm_rhs ||
            StateRoot(manifest.parent_state) != manifest.parent.state_root) return fail("parent");
    }
    std::set<arith_uint256> paid;
    std::vector<StateEntry> next;
    uint256 last;
    bool have_last{false};
    const uint32_t parent_min = std::max<int64_t>(1, int64_t{previous->nHeight} - MAX_SHARE_AGE);
    const uint32_t eligible_min = std::max<int64_t>(consensus.SharePoolHeight, int64_t{height} - MAX_SHARE_AGE);
    for (const auto& entry : manifest.parent_state) {
        if (entry.origin_height < parent_min || entry.origin_height > uint32_t(previous->nHeight) ||
            (have_last && !LessProof(last, entry.proof_id))) return fail("state");
        last = entry.proof_id;
        have_last = true;
        paid.insert(UintToArith256(entry.proof_id));
        if (entry.origin_height >= eligible_min) next.push_back(entry);
    }
    have_last = false;
    for (const auto& share : manifest.shares) {
        const auto& header = share.header;
        std::string error;
        if (!CheckShare(share, previous, block.nTime, consensus, error)) return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, error);
        if (share.origin.pool != current.pool) return fail("proof");
        const uint256 id = header.GetHash();
        if ((have_last && !LessProof(last, id)) ||
            !paid.insert(UintToArith256(id)).second) return fail("shares");
        next.push_back({uint32_t(header.m_height), id});
        last = id;
        have_last = true;
    }
    std::sort(next.begin(), next.end(), [](const auto& a, const auto& b) { return LessProof(a.proof_id, b.proof_id); });
    if (next.size() > MAX_STATE || StateRoot(next) != current.state_root || SharesRoot(manifest.shares) != current.shares_root) return fail("state");
    CAmount total{0};
    for (const auto& payout : payouts) {
        if (!MoneyRange(payout.nValue) || payout.nValue > MAX_MONEY - total) return fail("payout");
        total += payout.nValue;
    }
    if ((expected_reward && total != *expected_reward) || PayoutsRoot(payouts) != current.payouts_root ||
        payouts != CalculatePayouts(manifest, total)) return fail("payout");
    return true;
}
} // namespace sharepool

bool CheckSharePoolBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensus,
                        const CBlockIndex* pindex_prev, std::optional<CAmount> expected_reward)
{
    const int64_t height = pindex_prev ? int64_t{pindex_prev->nHeight} + 1 : 0;
    if (consensus.SharePoolHeight == std::numeric_limits<int>::max() || height < consensus.SharePoolHeight) return true;
    return sharepool::CheckActiveBlock(block, state, consensus, pindex_prev, expected_reward);
}
