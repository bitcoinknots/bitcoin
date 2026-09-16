// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SHAREPOOL_HASH_STORE_H
#define BITCOIN_SHAREPOOL_HASH_STORE_H

#include <consensus/sharepool_hash.h>
#include <dbwrapper.h>
#include <kernel/cs_main.h>
#include <sharepool/hash_requests.h>
#include <threadsafety.h>
#include <util/fs.h>

#include <map>
#include <set>
#include <deque>
#include <functional>
#include <utility>

class AutoFile;

namespace sharepool {
/** Content-addressed, fsynced evidence. Storage is not validation/ACK.
 * All pools and historical snapshots are retained independently of miner relay
 * membership. Finite local quotas leave blocks pending; they never change validity.
 */
class HashSnapshotStore {
public:
    /** Owned content preparation, not storage, validation or availability.
     * Only PreparePut constructs these bindings. Callers cannot replace the
     * owned bytes, decoded template metadata, hash or selected profile.
     */
    class PreparedSnapshot {
        friend class HashSnapshotStore;
        const uint32_t m_profile;
        const uint256 m_hash;
        std::vector<unsigned char> m_bytes;
        std::optional<hashonly::Snapshot> m_snapshot;
        PreparedSnapshot(uint32_t profile, uint256 hash, std::vector<unsigned char> bytes,
                         std::optional<hashonly::Snapshot> snapshot)
            : m_profile{profile}, m_hash{hash}, m_bytes{std::move(bytes)}, m_snapshot{std::move(snapshot)} {}
    public:
        PreparedSnapshot(PreparedSnapshot&&) = default;
        PreparedSnapshot(const PreparedSnapshot&) = delete;
        const uint256& Hash() const { return m_hash; }
    };
    struct Options {
        // Positive logical snapshot byte quota including per-record and
        // per-template-source index allowances, excluding LevelDB compaction.
        // Disk exhaustion still leaves dependent blocks pending.
        uint64_t max_bytes{1024ULL * 1024 * 1024};
        // Reconstruct disposable metadata from authenticated payloads. An
        // interrupted rebuild resumes from its last atomic batch checkpoint.
        bool rebuild_index{false};
        // Checked between durable bounded startup batches. Cancellation leaves
        // the last committed cursor available for the next ordinary startup.
        std::function<bool()> interrupted;
    };
    struct StartupStats {
        bool fast_path{false};
        bool resumed_rebuild{false};
        uint64_t records_scanned{0};
        uint64_t bytes_scanned{0};
        uint64_t batches{0};
    };
    struct Page {
        std::vector<uint256> hashes;
        std::optional<uint256> next;
        bool complete{false};
    };
    struct ArchiveResult {
        uint64_t records{0};
        uint64_t bytes{0};
        std::optional<uint256> next;
        bool complete{false};
    };
    struct RecentEntry {
        uint64_t sequence{0};
        uint256 hash;
    };
    struct RecentPage {
        std::vector<RecentEntry> entries;
        uint64_t next{0};
        uint64_t latest{0};
        bool gap{false};
        uint256 epoch;
    };
    static constexpr size_t MAX_INVENTORY_PAGE{1024};
    static constexpr size_t MAX_RECENT_INVENTORY{4096};
    static constexpr uint64_t MAX_ARCHIVE_CHUNK_BYTES{256ULL * 1024 * 1024};

private:
    friend struct HashSnapshotStoreTest;
    const uint32_t m_profile_version;
    const Options m_options;
    // CDBWrapper::NewIterator is non-const even for a read-only traversal.
    mutable CDBWrapper m_db;
    StartupStats m_startup_stats GUARDED_BY(cs_main);
    mutable bool m_repair_required GUARDED_BY(cs_main){false};
    // Quarantined records still consume their disk quota, but are neither
    // advertised nor considered available. A verified Put can replace them.
    uint64_t m_count GUARDED_BY(cs_main){0};
    uint64_t m_quarantined_count GUARDED_BY(cs_main){0};
    std::deque<RecentEntry> m_recent_inventory GUARDED_BY(cs_main);
    uint64_t m_recent_sequence GUARDED_BY(cs_main){0};
    const uint256 m_recent_epoch;
    std::map<uint256, std::shared_ptr<const std::vector<unsigned char>>> m_cache GUARDED_BY(cs_main);
    std::map<uint256, uint64_t> m_touched GUARDED_BY(cs_main);
    std::map<uint256, std::shared_ptr<const CBlock>> m_pending GUARDED_BY(cs_main);
    std::map<uint256, size_t> m_pending_sizes GUARDED_BY(cs_main);
    // Independently authenticated fallback sources, bounded per template ID.
    std::map<uint256, std::vector<std::pair<uint256, uint32_t>>> m_template_sources GUARDED_BY(cs_main);
    std::map<uint256, size_t> m_template_sizes GUARDED_BY(cs_main);
    std::map<Wtxid, size_t> m_transaction_sizes GUARDED_BY(cs_main);
    std::map<Wtxid, size_t> m_transaction_references GUARDED_BY(cs_main);
    std::map<Wtxid, CTransactionRef> m_transactions GUARDED_BY(cs_main);
    std::map<Wtxid, uint64_t> m_transaction_touched GUARDED_BY(cs_main);
    std::set<Wtxid> m_quarantined_transactions GUARDED_BY(cs_main);
    std::set<uint256> m_quarantined_templates GUARDED_BY(cs_main);
    std::map<uint256, CAmount> m_native_validated GUARDED_BY(cs_main);
    std::map<uint256, uint64_t> m_native_touched GUARDED_BY(cs_main);
    struct CapturedEntry {
        std::shared_ptr<const hashonly::CapturedTemplate> body;
        size_t charge;
        uint64_t touched;
    };
    std::map<uint256, CapturedEntry> m_captured_templates GUARDED_BY(cs_main);
    size_t m_captured_template_bytes GUARDED_BY(cs_main){0};
    HashRequestQueue<uint256> m_requests GUARDED_BY(cs_main);
    size_t m_bytes GUARDED_BY(cs_main){0};
    uint64_t m_charged_bytes GUARDED_BY(cs_main){0};
    size_t m_cache_bytes GUARDED_BY(cs_main){0};
    size_t m_pending_bytes GUARDED_BY(cs_main){0};
    size_t m_template_bytes GUARDED_BY(cs_main){0};
    size_t m_transaction_cache_bytes GUARDED_BY(cs_main){0};
    uint64_t m_revision GUARDED_BY(cs_main){0};
    uint64_t m_clock GUARDED_BY(cs_main){0};
    void Cache(const uint256& hash, std::shared_ptr<const std::vector<unsigned char>> bytes) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void Quarantine(const uint256& hash, std::optional<size_t> disk_size = std::nullopt) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    using SourceUpdates = std::map<uint256, std::vector<std::pair<uint256, uint32_t>>>;
    void PlanTemplateSources(const uint256& hash, const hashonly::Snapshot& snapshot,
                             SourceUpdates& updates, const std::set<uint256>& staged = {}) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void StartIndexRebuild() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool RebuildIndexBatch() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void MarkRepairRequired() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void ArchiveLocalTemplates(const hashonly::Snapshot& snapshot) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::vector<std::pair<uint256, uint32_t>> TemplateSources(const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    CTransactionRef Transaction(const Wtxid& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void CacheTransaction(const Wtxid& id, CTransactionRef tx) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void QuarantineTransaction(const Wtxid& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::shared_ptr<const CBlock> LocalTemplate(const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

public:
    explicit HashSnapshotStore(const fs::path& path, bool memory_only = false,
                               uint32_t profile_version = hashonly::VERSION);
    HashSnapshotStore(const fs::path& path, bool memory_only, uint32_t profile_version, Options options);
    /** Advisory index availability. Only GetShared/Lookup authenticate payload
     * bytes; callers must never use Has as a consensus validation result. */
    bool Has(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::optional<std::vector<unsigned char>> Get(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::shared_ptr<const std::vector<unsigned char>> GetShared(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::shared_ptr<const hashonly::Snapshot> Lookup(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Hash and decode owned bytes without accessing the store. P2P/RPC callers
     * run this outside cs_main. A requested hash mismatch fails before decode;
     * hash-bound malformed bytes remain evidence for later native validation.
     */
    static PreparedSnapshot PreparePut(std::vector<unsigned char> raw, uint32_t profile_version,
                                       std::optional<uint256> expected = std::nullopt);
    /** Recheck current durable evidence, quota and index state before committing.
     * Preparation neither reserves storage nor bypasses a fresh durable read.
     * The consumed bytes become empty; reusing a consumed preparation fails.
     * Durable reads/writes and index operations still execute under cs_main.
     */
    uint256 PutPrepared(PreparedSnapshot& prepared) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    uint256 Put(Span<const unsigned char> raw, std::optional<uint256> expected = std::nullopt) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::vector<uint256> Inventory() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Bounded disk-index traversal; next is an opaque exclusive cursor. A
     * page may be empty when scanned records are quarantined. */
    Page InventoryPage(std::optional<uint256> after = std::nullopt,
                       size_t limit = MAX_INVENTORY_PAGE) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Bounded live announcement ring, independent of archive length. A gap
     * means the cursor predates retained events or belongs to a prior restart;
     * callers continue archive reconciliation instead of assuming completeness.
     */
    RecentPage RecentInventory(uint64_t after = 0, size_t limit = 256) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    uint64_t RecentSequence() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_recent_sequence; }
    /** Portable, bounded archive chunks. Hashes are verified on export and
     * import; records already imported remain durable if a later record fails.
     * The caller owns file creation, fsync/close and administrative access.
     * Call without cs_main: file I/O and transcript hashing run outside it;
     * individual bounded store reads/writes take short internal lock scopes. */
    ArchiveResult ExportArchive(AutoFile& file, std::optional<uint256> after = std::nullopt,
                                size_t record_limit = MAX_INVENTORY_PAGE,
                                uint64_t byte_limit = MAX_ARCHIVE_CHUNK_BYTES);
    ArchiveResult ImportArchive(AutoFile& file, size_t record_limit = MAX_INVENTORY_PAGE,
                                uint64_t byte_limit = MAX_ARCHIVE_CHUNK_BYTES);
    std::vector<uint256> Needed() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::vector<uint256> Speculative() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Unscoped callers offer low-priority hints, never block requirements. */
    void Need(const std::vector<uint256>& hashes) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void NeedForBlock(const uint256& block, const std::vector<uint256>& hashes) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void Requested(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    uint64_t Revision() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_revision; }
    size_t Bytes() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_bytes; }
    uint64_t ChargedBytes() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_charged_bytes; }
    uint64_t Count() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_count - m_quarantined_count; }
    uint64_t MaxBytes() const { return m_options.max_bytes; }
    const StartupStats& GetStartupStats() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_startup_stats; }
    bool RepairRequired() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_repair_required; }
    size_t TemplateBytes() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_template_bytes; }
    size_t TemplateCount() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_template_sizes.size() - m_quarantined_templates.size(); }
    void RememberTemplate(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::shared_ptr<const CBlock> Template(const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Byte-derived reuse only. The caller must obtain currently available
     * evidence through Template first; this cache never supplies availability,
     * ancestry, proof, authorization, native validity or settlement verdicts. */
    std::shared_ptr<const hashonly::CapturedTemplate> FindCapturedTemplate(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void RememberCapturedTemplate(std::shared_ptr<const hashonly::CapturedTemplate> body) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::optional<CAmount> NativeValidated(const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void SetNativeValidated(const uint256& id, CAmount reward) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool QueueBlock(std::shared_ptr<const CBlock> block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Body retained for local validation; this does not imply block validity. */
    bool HasPendingBlock(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Exact witness-inclusive retained body, not merely its header identity. */
    bool MatchesPendingBlock(const CBlock& block) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void RemoveBlock(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::vector<std::shared_ptr<const CBlock>> PendingBlocks() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
};
} // namespace sharepool
#endif
