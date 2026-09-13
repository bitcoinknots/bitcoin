// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHAREPOOL_TIDES_HISTORY_H
#define BITCOIN_SHAREPOOL_TIDES_HISTORY_H

#include <sharepool/tides.h>

#include <functional>
#include <memory>
#include <string>
#include <string_view>

class CBlockIndex;

namespace sharepool::tides {

/** Immutable summary of a natively verified admission. The payout script is a
 * recipient, not an exclusive identity; the same script may occur in many pools.
 */
struct Admission {
    uint256 proof_id;
    uint256 pool;
    std::vector<unsigned char> payout_script;
    uint256 work;
    uint32_t admission_height{0}; // Derived from the verified containing native block.
};

/** The fetch callback must authenticate the exact snapshot commitment, native
 * branch/binding, signature and previously validated admissions before Ready.
 * Admissions are in strictly increasing numeric proof-ID order across pools.
 */
struct HistoryDelta {
    uint256 block_hash;
    uint256 parent_hash;
    uint256 snapshot_hash;
    uint32_t height{0};
    size_t encoded_bytes{0};
    std::vector<Admission> admissions;
};

enum class HistoryStatus { Ready, MissingData, Invalid, ResourceLimit };

struct DeltaResult {
    HistoryStatus status{HistoryStatus::MissingData};
    std::shared_ptr<const HistoryDelta> delta;
    std::vector<uint256> missing;
    std::string reason;

    static DeltaResult Ready(std::shared_ptr<const HistoryDelta> value);
    static DeltaResult Missing(std::vector<uint256> hashes, std::string reason = "tides-history-missing");
    static DeltaResult Invalid(std::string reason);
    static DeltaResult Limited(std::string reason);
};

using FetchHistoryDelta = std::function<DeltaResult(const CBlockIndex&)>;

struct HistoryBudget {
    size_t blocks{4096};
    size_t entries{65536};
    size_t bytes{64 * 1024 * 1024};
};

struct HistoryCacheBudget {
    size_t blocks{4096};
    size_t bytes{64 * 1024 * 1024};
    size_t queries{16};
    size_t query_bytes{64 * 1024 * 1024};
    bool operator==(const HistoryCacheBudget&) const = default;
};

/** Strict positive MiB values with checked conversion to the platform's byte
 * size. Zero and unlimited sentinels are rejected. These are per-thread derived-cache budgets,
 * not consensus limits or a reservation of physical RAM. */
HistoryCacheBudget HistoryCacheBudgetFromMiB(std::string_view cache_mib, std::string_view query_mib);
/** Process configuration used by native payout validation and mining RPCs.
 * Existing per-thread indexes apply updates on their next call. */
void ConfigureHistoryCache(HistoryCacheBudget budget);
HistoryCacheBudget ConfiguredHistoryCacheBudget();

struct HistoryWindow {
    HistoryStatus status{HistoryStatus::MissingData};
    std::string reason;
    std::vector<uint256> missing;
    // Chronological suffix, populated ONLY on Ready. Sequence starts at 1 in
    // this returned suffix; these positions are not global receipt counters.
    std::vector<LogEntry> entries;
    bool complete_to_activation{false};
    size_t scanned_blocks{0}; // Progress made by this call, including cache hits.
    size_t scanned_entries{0};
    size_t scanned_bytes{0};
};

/** Optional local acceleration. Implementations cannot change payout rules:
 * callers fall back to the authenticated snapshot scan when unavailable or
 * locally budget-limited. In particular an absent/corrupt index is not an empty
 * pool. The reader must not acquire the chain lock while holding a local
 * index lock, or retain that lock across a fetch callback. */
class PersistentHistoryReader {
public:
    virtual ~PersistentHistoryReader() = default;
    virtual bool MatchesScope(const uint256& genesis, const uint256& rules,
                              uint32_t profile, uint32_t activation_height) const = 0;
    virtual HistoryWindow ReadPool(const CBlockIndex* previous, uint32_t activation_height,
                                   const uint256& pool, const Work& required_work,
                                   const FetchHistoryDelta& fetch, HistoryBudget budget = {}) = 0;
};
void ConfigurePersistentHistoryReader(std::shared_ptr<PersistentHistoryReader> reader);
std::shared_ptr<PersistentHistoryReader> ConfiguredPersistentHistoryReader();

/** Derived local cache, never a source of consensus authority or disk history.
 * Stored native snapshots retain the immutable deltas. Each query is keyed by
 * the exact parent header/branch, activation, pool and requested work. Reorgs
 * select a different parent; no destructive mutation of another branch occurs.
 * No chain-index pointers survive a call: resumptions resolve their saved
 * height/hash from the caller's newly supplied parent. Clear discards all local
 * derived state when explicitly resetting/reindexing the surrounding profile.
 *
 * ReadPool returns enough newest pool work including every proof in the oldest
 * selected native-height batch, or explicitly reaches activation.
 * It never confuses missing/budget-limited history with an empty pool. A bounded
 * query cursor retains progress across identical calls, including missing-data
 * retries and long scans through blocks with no admissions for the pool.
 * Local limits are not consensus rules. Callback/local failures remain missing
 * or ResourceLimit; only authenticated malformed admissions can be Invalid.
 *
 * Not thread-safe. The caller owns synchronization and the supplied index's
 * lifetime for the duration of each call.
 * Fetch callbacks must independently bound decoding before returning a delta.
 */
class HistoryIndex {
    struct Impl;
    std::unique_ptr<Impl> m_impl;

public:
    explicit HistoryIndex(HistoryCacheBudget budget = {});
    ~HistoryIndex();
    HistoryIndex(const HistoryIndex&) = delete;
    HistoryIndex& operator=(const HistoryIndex&) = delete;
    void Clear();
    /** Raising a budget preserves unfinished cursors. Reducing it may evict
     * derived queries/deltas, which are reconstructed from anchored snapshots.
     * No native admission or payout right is discarded by an eviction. */
    void SetCacheBudget(HistoryCacheBudget budget);
    HistoryWindow ReadPool(const CBlockIndex* previous, uint32_t activation_height,
                           const uint256& pool, const Work& required_work,
                           const FetchHistoryDelta& fetch, HistoryBudget budget = {});
};
} // namespace sharepool::tides

#endif // BITCOIN_SHAREPOOL_TIDES_HISTORY_H
