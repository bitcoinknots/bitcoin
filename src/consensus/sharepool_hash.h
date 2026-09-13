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
inline constexpr uint32_t LEDGER_VERSION{5};
inline constexpr uint32_t TIDES_VERSION{6};
// Vector limits include their CompactSize count prefix. Confirmed credits are
// never truncated: fresh admissions must stop when pending capacity is full.
inline constexpr uint32_t MAX_PENDING_BYTES{4 * 1024 * 1024};
inline constexpr uint32_t MAX_SETTLED_BYTES{1024 * 1024};
inline constexpr uint32_t MAX_CERTIFICATE_BYTES{4 * 1024 * 1024};
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

struct LedgerCredit {
    uint32_t admitted_height{0};
    uint32_t origin_height{0};
    uint256 proof_id;
    uint256 pool;
    uint32_t native_bits{0};
    std::vector<unsigned char> payout_script;
    SERIALIZE_METHODS(LedgerCredit, obj)
    {
        READWRITE(obj.admitted_height, obj.origin_height, obj.proof_id, obj.pool, obj.native_bits, obj.payout_script);
    }
    bool operator==(const LedgerCredit&) const = default;
};

struct OriginCertificate {
    uint32_t origin_height{0};
    uint256 native_parent;
    uint256 identity;
    uint256 snapshot_hash;
    SERIALIZE_METHODS(OriginCertificate, obj)
    {
        READWRITE(obj.origin_height, obj.native_parent, obj.identity, obj.snapshot_hash);
    }
    bool operator==(const OriginCertificate&) const = default;
};

struct Snapshot {
    Envelope binding;
    Signature authorization{};
    uint256 job_commitment; // Full normalized body with m_mm_rhs zero; no signature fixed point.
    std::vector<TemplateRecord> templates;
    std::vector<Share> shares;
    std::vector<StateEntry> post_state;
    std::vector<CTxOut> payouts;
    // v5 only: native-parent-confirmed admissions, the current deterministic
    // payout prefix, and recent exact-body validation certificates.
    std::vector<LedgerCredit> pending;
    std::vector<LedgerCredit> settled;
    std::vector<OriginCertificate> certificates;
    // v6 only: cumulative commitment to canonical admission deltas. Historical
    // proofs stay in their original snapshots, not repeated pending arrays.
    uint256 history_head;

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
/** Explicit profile for untrusted bytes. Legacy raw hashing stays frozen. */
uint256 ProfileSnapshotHash(Span<const unsigned char> bytes, uint32_t version);
uint256 ProfileSnapshotHash(const Snapshot& snapshot, uint32_t version);
uint32_t ProfileVersion(const Consensus::Params& consensus);
uint256 RulesHash(uint32_t version = VERSION);
uint256 SnapshotContentsHash(const Snapshot& snapshot);
uint256 OwnerHash(const Envelope& binding, const uint256& job, const uint256& contents);
uint256 OwnerHash(const Snapshot& snapshot);
uint256 JobHash(const CBlock& block);
/** v5 exact normalized header (including RHS), then ordered witness txids. */
uint256 OriginCertificateId(const CBlock& block);
/** Derive v5 arrays from an authenticated actual native parent's snapshot.
 * Fresh proofs must separately pass CheckSnapshot's proof/native validation.
 * A null parent is permitted only by the caller's activation-height rule.
 * Throws invalid_argument for invalid state and ios_base::failure for bounds;
 * local allocation failures propagate. No confirmed pending credit expires.
 */
void ApplyLedgerState(Snapshot& snapshot, const Snapshot* parent);
void ApplyTidesState(Snapshot& snapshot, const Snapshot* parent);
/** Deterministic target derived from the contextual native nBits; throws on malformed compact. */
uint256 ShareTarget(uint32_t native_bits, uint32_t version = VERSION);
/** v6 assigned proof work is an exact power of two in expected-hash units. */
uint256 TidesShareWork(uint32_t native_bits);
/** Identical normalization and single-SHA256 display convention to RelayTemplateId. */
std::vector<unsigned char> NormalizedHeader(const CBlockHeader& header);
uint256 TemplateId(const CBlockHeader& header);
std::vector<CTxOut> CalculatePayouts(const Snapshot& snapshot, CAmount reward);
/** Current job admissions extend actual-parent history. Full native reward is
 * required: flooring residue is unclaimed, never inferred from coinbase totals.
 * reserve_scripts returns zero-valued slots for every eligible script so the
 * native builder can reserve space before selecting fee-paying transactions.
 */
Result CalculateTidesPayouts(const Snapshot& snapshot, const CBlockIndex* previous,
                            uint32_t native_bits, const Consensus::Params& consensus,
                            const Lookup& lookup, CAmount reward,
                            std::vector<CTxOut>& payouts, bool reserve_scripts = false);

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
/** Mining-only structural check: reserve one dependency edge and the current
 * full body for a future settlement's origin walk. The caller still validates
 * this job's native body. Do not use this policy check for block acceptance:
 * a consensus-valid boundary-depth block may be unsuitable for new share work.
 * Passing cannot guarantee later aggregate byte capacity, ancestry or payment.
 * Local failures unrelated to malformed input may propagate as exceptions.
 */
Result CheckMiningJob(const CBlock& block, const CBlockIndex* previous,
                      const Consensus::Params& consensus, const Lookup& lookup,
                      const ValidateOrigin& validate_origin,
                      std::optional<CAmount> expected_reward = std::nullopt,
                      bool allow_unsigned = false);
/** Historical normalized full-body validation using the current native
 * parent's v5 certificates, with no future-mining depth reservation. */
Result CheckHistoricalTemplate(const CBlock& full_origin, const CBlockIndex* settlement_parent,
                               uint32_t settlement_time, const Consensus::Params& consensus,
                               const Lookup& lookup, const ValidateOrigin& validate_origin);
/** Standalone proof admission reserves its future settlement embedding edge;
 * paid-state/repeat-payment checks remain settlement rules. */
Result CheckShareProof(const Share& share, const CBlock& full_origin,
                       const CBlockIndex* settlement_parent, uint32_t settlement_time,
                       const Consensus::Params& consensus, const Lookup& lookup,
                       const ValidateOrigin& validate_origin);
} // namespace sharepool::hashonly

#endif // BITCOIN_CONSENSUS_SHAREPOOL_HASH_H
