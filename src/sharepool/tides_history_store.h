// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHAREPOOL_TIDES_HISTORY_STORE_H
#define BITCOIN_SHAREPOOL_TIDES_HISTORY_STORE_H

#include <sharepool/tides_history.h>
#include <util/fs.h>

namespace sharepool::tides {

/** Rebuildable, native-node-owned history accelerator. Each covered native
 * block has a sealed persistent map from pool to its last admission batch;
 * batches link only to that pool's previous batch on the same branch. Updating
 * a block copies changed Patricia-map paths, not the entire pool registry.
 *
 * Coverage is written only for BLOCK_VALID_SCRIPTS ancestors after the caller
 * authenticates their exact snapshot deltas. Selected batches are re-fetched
 * and compared before returning payout data. Conditional branches and absent,
 * corrupt or budget-limited local records stay unavailable, never empty.
 *
 * The owner-only seal.key is separate from the disposable index/ database.
 * It authenticates local coverage against database tampering/corruption, not
 * host compromise. This key grants no mining or spending authority. Losing it
 * requires an explicit rebuild; it cannot authenticate imported index data.
 * Neither the map root nor its seal changes the flat native snapshot hash.
 *
 * Thread-safe. Native status is checked under cs_main before acquiring the
 * local mutex. The mutex is released around status checks and fetch callbacks,
 * preventing a chain/index lock-order inversion. Query budgets cover retained
 * summaries; returning a completed result temporarily also allocates its copy.
 */
class PersistentHistoryIndex final : public PersistentHistoryReader {
public:
    struct Scope {
        uint256 genesis;
        uint256 rules;
        uint32_t profile{0};
        uint32_t activation_height{0};
        bool operator==(const Scope&) const = default;
    };
    struct Options {
        uint64_t max_bytes{1024ULL * 1024 * 1024}; // Logical index charge, excluding LevelDB compaction.
        size_t cache_bytes{8 * 1024 * 1024};
        bool rebuild{false}; // Discards only this derived local index.
    };
    struct Stats {
        uint64_t covered_blocks{0};
        uint64_t pool_batches{0};
        uint64_t map_nodes{0};
        uint64_t charged_bytes{0};
    };

    PersistentHistoryIndex(const fs::path& path, Scope scope, Options options, bool memory_only = false);
    ~PersistentHistoryIndex() override;
    PersistentHistoryIndex(const PersistentHistoryIndex&) = delete;
    PersistentHistoryIndex& operator=(const PersistentHistoryIndex&) = delete;
    bool MatchesScope(const uint256& genesis, const uint256& rules,
                      uint32_t profile, uint32_t activation_height) const override;
    HistoryWindow ReadPool(const CBlockIndex* previous, uint32_t activation_height,
                           const uint256& pool, const Work& required_work,
                           const FetchHistoryDelta& fetch, HistoryBudget budget = {}) override;
    Stats GetStats() const;

private:
    friend struct PersistentHistoryIndexTest;
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};
} // namespace sharepool::tides
#endif // BITCOIN_SHAREPOOL_TIDES_HISTORY_STORE_H
