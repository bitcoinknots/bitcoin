// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SHAREPOOL_HASH_H
#define BITCOIN_CONSENSUS_SHAREPOOL_HASH_H

#include <consensus/sharepool.h>

#include <functional>
#include <memory>
#include <stdexcept>

/** Separately versioned hash-only profile. No network access or legacy activation. */
namespace sharepool::hashonly {
inline constexpr uint32_t VERSION{4};
inline constexpr uint32_t SHARE_TARGET_SHIFT{10}; // Expected ~1024 proofs per native block at unclamped difficulty.
inline constexpr uint32_t MAX_SNAPSHOT_BYTES{16 * 1024 * 1024};
inline constexpr uint32_t MAX_TEMPLATE_BYTES{4'000'000};
inline constexpr uint32_t MAX_EXPANDED_TEMPLATE_BYTES{512 * 1024 * 1024};
inline constexpr uint32_t MAX_TEMPLATE_TX_REFERENCES{2'000'000};
inline constexpr uint32_t MAX_ORIGIN_CHECKS{2048};
inline constexpr uint32_t MAX_DEPENDENCY_DEPTH{64};
inline constexpr uint32_t MAX_DEPENDENCY_BYTES{64 * 1024 * 1024};

struct TemplateRecord {
    uint256 id;
    CBlock block; // Transactions share immutable references after canonical table decoding.
};

struct Snapshot {
    Envelope binding;
    Signature authorization{};
    uint256 job_commitment; // Full normalized body with m_mm_rhs zero; no signature fixed point.
    std::vector<TemplateRecord> templates;
    std::vector<Share> shares;
    std::vector<StateEntry> post_state;
    std::vector<CTxOut> payouts;

    Snapshot() { binding.version = VERSION; }
};

enum class Status { Valid, MissingData, Invalid };

struct Result {
    Status status{Status::Invalid};
    std::string reason;
    std::vector<uint256> missing;
    /** Required on successful full-origin validation: actual subsidy plus fees. */
    std::optional<CAmount> expected_reward;

    bool IsValid() const { return status == Status::Valid; }
    bool IsMissing() const { return status == Status::MissingData; }
    static Result Valid(std::optional<CAmount> reward = std::nullopt)
    {
        return {Status::Valid, {}, {}, reward};
    }
    static Result Missing(std::vector<uint256> hashes = {}, std::string reason = "bad-sharepool-hash-missing-data")
    {
        return {Status::MissingData, std::move(reason), std::move(hashes), std::nullopt};
    }
    static Result Invalid(std::string reason)
    {
        return {Status::Invalid, std::move(reason), {}, std::nullopt};
    }
};

/** Lookup is local and content-addressed. A missing response is not invalidity. */
using Lookup = std::function<std::shared_ptr<const Snapshot>(const uint256&)>;
/** Lookup may throw this only after authenticating the exact requested hash.
 * A malformed authenticated preimage is invalidity, not data unavailability. */
class MalformedSnapshot : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
/** Native current/historical body validation, excluding recursive v2 checks.
 * On Valid, return the actual native subsidy + verified fees in expected_reward.
 * The pure verifier separately checks the origin's v2 snapshot and dependencies.
 */
using ValidateOrigin = std::function<Result(const CBlock&, const CBlockIndex*)>;

std::vector<unsigned char> EncodeSnapshot(const Snapshot& snapshot);
Snapshot DecodeSnapshot(Span<const unsigned char> bytes);
/** Bounded full native-body decoders; native UTXO/witness rules remain external. */
CBlock DecodeTemplate(Span<const unsigned char> bytes);
CBlock DecodeBlock(Span<const unsigned char> bytes);
CTransactionRef DecodeTransaction(Span<const unsigned char> bytes);
uint256 SnapshotHash(const Snapshot& snapshot);
/** Hash exact bytes without decoding; callers must enforce canonical decoding. */
uint256 SnapshotHash(Span<const unsigned char> bytes);
uint256 RulesHash();
uint256 SnapshotContentsHash(const Snapshot& snapshot);
uint256 OwnerHash(const Envelope& binding, const uint256& job, const uint256& contents);
uint256 OwnerHash(const Snapshot& snapshot);
uint256 JobHash(const CBlock& block);
/** Deterministic target derived from the contextual native nBits; throws on malformed compact. */
uint256 ShareTarget(uint32_t native_bits);
/** Identical normalization and single-SHA256 display convention to RelayTemplateId. */
std::vector<unsigned char> NormalizedHeader(const CBlockHeader& header);
uint256 TemplateId(const CBlockHeader& header);
std::vector<CTxOut> CalculatePayouts(const Snapshot& snapshot, CAmount reward);

/** Does not check the containing block's ordinary native PoW/UTXO/script rules.
 * The caller supplies those checks and, when known, its actual reward.
 * All full origin bodies, including unused records, are checked through callback.
 * Parent state is opened from its already active-chain-anchored snapshot; origin
 * dependency recursion is bounded and owns the v2 checks (callback must not recurse).
 */
Result CheckSnapshot(const CBlock& block, const CBlockIndex* previous,
                     const Consensus::Params& consensus, const Lookup& lookup,
                     const ValidateOrigin& validate_origin,
                     std::optional<CAmount> expected_reward = std::nullopt,
                     uint32_t depth = 0, bool allow_unsigned = false);
/** Standalone proof admission; paid-state/repeat-payment checks remain settlement rules. */
Result CheckShareProof(const Share& share, const CBlock& full_origin,
                       const CBlockIndex* settlement_parent, uint32_t settlement_time,
                       const Consensus::Params& consensus, const Lookup& lookup,
                       const ValidateOrigin& validate_origin);
} // namespace sharepool::hashonly

#endif // BITCOIN_CONSENSUS_SHAREPOOL_HASH_H
