// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SHAREPOOL_H
#define BITCOIN_CONSENSUS_SHAREPOOL_H

#include <consensus/amount.h>
#include <primitives/block.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <ios>
#include <optional>
#include <string>
#include <vector>

class BlockValidationState;
class CBlockIndex;
namespace Consensus { struct Params; }

/** Self-contained native regtest profile. No off-chain state selects validity. */
namespace sharepool {
inline constexpr uint32_t SHARE_BITS{0x207fffff};
inline constexpr uint32_t MAX_SHARE_AGE{3};
inline constexpr uint32_t MAX_SHARES{32};
inline constexpr uint32_t MAX_STATE{128};
inline constexpr uint32_t MAX_MANIFEST{65536};
inline constexpr uint8_t VARIABLE_SHARE_WORK_VERSION{8};
using Signature = std::array<unsigned char, 64>;

template <typename Stream, typename T>
void ReadBoundedVector(Stream& stream, std::vector<T>& values, size_t limit)
{
    const auto count = ReadCompactSize(stream);
    if (count > limit) throw std::ios_base::failure("sharepool vector exceeds bound");
    values.resize(count);
    for (auto& value : values) stream >> value;
}

struct Envelope {
    uint8_t version{1};
    uint256 genesis;
    uint256 rules;
    uint32_t height{0};
    uint256 native_parent;
    uint256 pool;
    std::array<unsigned char, 32> owner{};
    std::vector<unsigned char> payout_script;
    // V8 only: assigned expected hashes are exactly 2^share_work_bits.
    uint8_t share_work_bits{0};
    uint256 shares_root;
    uint256 state_root;
    uint256 payouts_root;

    template <typename Stream> void Serialize(Stream& s) const
    {
        if (version != VARIABLE_SHARE_WORK_VERSION && share_work_bits != 0) throw std::ios_base::failure("legacy share work assignment");
        s << version << genesis << rules << height << native_parent << pool << owner << payout_script;
        if (version == VARIABLE_SHARE_WORK_VERSION) s << share_work_bits;
        s << shares_root << state_root << payouts_root;
    }
    template <typename Stream> void Unserialize(Stream& s)
    {
        s >> version >> genesis >> rules >> height >> native_parent >> pool >> owner;
        ReadBoundedVector(s, payout_script, 34);
        share_work_bits = 0;
        if (version == VARIABLE_SHARE_WORK_VERSION) s >> share_work_bits;
        s >> shares_root >> state_root >> payouts_root;
    }
};

struct StateEntry {
    uint32_t origin_height{0};
    uint256 proof_id;
    SERIALIZE_METHODS(StateEntry, obj) { READWRITE(obj.origin_height, obj.proof_id); }
};

struct Share {
    CBlockHeader header;
    Envelope origin;
    Signature authorization{};
    SERIALIZE_METHODS(Share, obj) { READWRITE(obj.header, obj.origin, obj.authorization); }
};

struct Manifest {
    Envelope current;
    Signature authorization{};
    uint8_t has_parent{0};
    Envelope parent;
    std::vector<StateEntry> parent_state;
    std::vector<Share> shares;

    template <typename Stream> void Serialize(Stream& s) const
    {
        s << current << authorization << has_parent;
        if (has_parent) s << parent;
        s << parent_state << shares;
    }
    template <typename Stream> void Unserialize(Stream& s)
    {
        s >> current >> authorization >> has_parent;
        if (has_parent > 1) throw std::ios_base::failure("invalid sharepool parent flag");
        if (has_parent) s >> parent;
        ReadBoundedVector(s, parent_state, MAX_STATE);
        ReadBoundedVector(s, shares, MAX_SHARES);
    }
};

uint256 RulesHash();
uint256 EnvelopeHash(const Envelope& envelope);
uint256 OwnerHash(const Envelope& envelope);
uint256 StateRoot(const std::vector<StateEntry>& state);
uint256 SharesRoot(const std::vector<Share>& shares);
uint256 PayoutsRoot(const std::vector<CTxOut>& payouts);
bool IsPayoutScript(Span<const unsigned char> script);
std::vector<unsigned char> EncodeManifest(const Manifest& manifest);
Manifest DecodeManifest(Span<const unsigned char> bytes);
/** Decode the same canonical coinbase carrier used by native block validation. */
Manifest ParseCoinbaseManifest(const CTransaction& coinbase, std::vector<CTxOut>& payouts);
std::vector<CTxOut> CarrierOutputs(Span<const unsigned char> manifest);
std::vector<CTxOut> CalculatePayouts(const Manifest& manifest, CAmount reward);
/** Stateless native share admission; nullifier/pool-set checks remain block rules. */
bool CheckShare(const Share& share, const CBlockIndex* settlement_parent, uint32_t settlement_time,
                const Consensus::Params& consensus, std::string& error);
} // namespace sharepool

/** expected_reward is native subsidy plus verified transaction fees, when known. */
bool CheckSharePoolBlock(const CBlock& block, BlockValidationState& state,
                        const Consensus::Params& consensus, const CBlockIndex* pindex_prev,
                        std::optional<CAmount> expected_reward = std::nullopt);

#endif // BITCOIN_CONSENSUS_SHAREPOOL_H
