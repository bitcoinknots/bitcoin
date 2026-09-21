// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEMPLATEDIVERSITY_H
#define BITCOIN_TEMPLATEDIVERSITY_H

#include <consensus/amount.h>
#include <sync.h>
#include <uint256.h>
#include <validationinterface.h>

#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

class CBlock;
class CBlockUndo;
class ChainstateManager;
class CTxMemPool;

namespace node {

/**
 * How a block's transaction selection compared with this node's own mempool
 * at the moment the block arrived. Only available for blocks this node saw
 * connect live while synced; historical blocks have no mempool to compare to.
 */
struct LiveSelection {
    //! Mempool txs that had waited at least TEMPLATE_DIVERSITY_MIN_AGE and
    //! paid more (both alone and with ancestors) than the block's median
    //! included feerate, yet were left out.
    int64_t skipped_txs{0};
    CAmount skipped_fees{0};
    //! Mempool txs old enough to have been in any reasonable template.
    int64_t eligible_txs{0};
    //! Median feerate (sat/kvB) of block txs this node had in its mempool, if any.
    std::optional<int64_t> threshold_feerate;
};

/**
 * What a block reveals about the software and policy that built its template.
 *
 * structure_key deliberately ignores human-readable coinbase text: tags are
 * claims anyone can write, while output layout, witness commitment placement,
 * scriptSig push layout, locktime/sequence conventions and version-bit use
 * come from the template-building code itself.
 */
struct BlockFingerprint {
    uint256 hash;
    int height{0};
    std::string structure_key;
    std::string coinbase_tag;
    size_t tx_count{0};
    bool have_undo{false};
    int64_t datacarrier_bytes{0};
    int64_t datacarrier_txs{0};
    //! Percentage of adjacent non-coinbase tx pairs in non-increasing feerate order; -1 if fewer than 3 txs.
    int feerate_ordered_pct{-1};
    //! Median non-coinbase feerate in sat/kvB; -1 if none.
    int64_t median_feerate{-1};
};

static constexpr int64_t TEMPLATE_DIVERSITY_MIN_AGE_SECONDS{60};
static constexpr size_t TEMPLATE_DIVERSITY_LIVE_WINDOW{2016};
//! A live sample counts as a heavy skip at or above this many skipped txs.
static constexpr int64_t TEMPLATE_DIVERSITY_HEAVY_SKIP{10};

/** The structure key alone (see BlockFingerprint::structure_key). */
std::string BlockStructureKey(const CBlock& block);

/** Fingerprint a block. Undo data is optional; without it, fee- and datacarrier-based fields stay unset. */
BlockFingerprint FingerprintBlock(const CBlock& block, const CBlockUndo* undo, int height);

class TemplateDiversityTracker;

struct FingerprintWindow {
    //! Newest first.
    std::vector<std::pair<BlockFingerprint, std::optional<LiveSelection>>> blocks;
    int unavailable{0};
};

/** Fingerprint up to nblocks blocks back from the active tip, attaching live data where the tracker has it. */
FingerprintWindow CollectRecentFingerprints(ChainstateManager& chainman, const TemplateDiversityTracker* tracker, int nblocks);

/** Records LiveSelection for each block connected while this node is synced. */
class TemplateDiversityTracker final : public CValidationInterface
{
public:
    TemplateDiversityTracker(const ChainstateManager& chainman, const CTxMemPool& mempool);

    std::optional<LiveSelection> GetLiveSelection(const uint256& block_hash) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Exclude a block submitted through this node's RPC from network structure counts. Call before processing it.
    void MarkLocalSubmission(const uint256& block_hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    struct StructureShare {
        int64_t blocks{0};
        int64_t sample{0};
    };
    //! How many of the last TEMPLATE_DIVERSITY_LIVE_WINDOW connected, non-local blocks used this structure.
    StructureShare GetChainStructureShare(const std::string& structure_key) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

protected:
    void MempoolTransactionsRemovedForBlock(const std::vector<RemovedMempoolTransactionInfo>& txs_removed_for_block, unsigned int nBlockHeight) override;
    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override;

private:
    const ChainstateManager& m_chainman;
    const CTxMemPool& m_mempool;

    mutable Mutex m_mutex;
    //! Median included feerate per height, from the removal signal that precedes BlockConnected.
    std::map<unsigned int, std::optional<int64_t>> m_pending_threshold GUARDED_BY(m_mutex);
    std::map<uint256, LiveSelection> m_live GUARDED_BY(m_mutex);
    std::deque<uint256> m_live_order GUARDED_BY(m_mutex);
    std::map<std::string, int64_t> m_chain_counts GUARDED_BY(m_mutex);
    std::deque<std::string> m_chain_order GUARDED_BY(m_mutex);
    std::set<uint256> m_local_submissions GUARDED_BY(m_mutex);
    std::deque<uint256> m_local_order GUARDED_BY(m_mutex);
};

} // namespace node

#endif // BITCOIN_TEMPLATEDIVERSITY_H
