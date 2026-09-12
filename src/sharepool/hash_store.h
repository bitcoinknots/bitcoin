// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SHAREPOOL_HASH_STORE_H
#define BITCOIN_SHAREPOOL_HASH_STORE_H

#include <consensus/sharepool_hash.h>
#include <dbwrapper.h>
#include <kernel/cs_main.h>
#include <threadsafety.h>
#include <util/fs.h>

#include <map>
#include <set>

namespace sharepool {
/** Content-addressed, fsynced v2 evidence. Storage is not validation/ACK.
 * All pools and historical snapshots are retained independently of miner relay
 * membership. Finite local quotas leave blocks pending; they never change validity.
 */
class HashSnapshotStore {
    CDBWrapper m_db;
    // Quarantined records still consume their disk quota, but are neither
    // advertised nor considered available. A verified Put can replace them.
    std::map<uint256, size_t> m_sizes GUARDED_BY(cs_main);
    std::set<uint256> m_quarantined GUARDED_BY(cs_main);
    std::map<uint256, std::shared_ptr<const std::vector<unsigned char>>> m_cache GUARDED_BY(cs_main);
    std::map<uint256, uint64_t> m_touched GUARDED_BY(cs_main);
    std::map<uint256, std::shared_ptr<const CBlock>> m_pending GUARDED_BY(cs_main);
    std::map<uint256, size_t> m_pending_sizes GUARDED_BY(cs_main);
    std::map<uint256, std::pair<uint256, uint32_t>> m_template_sources GUARDED_BY(cs_main);
    std::map<uint256, size_t> m_template_sizes GUARDED_BY(cs_main);
    std::set<uint256> m_quarantined_templates GUARDED_BY(cs_main);
    std::map<uint256, CAmount> m_native_validated GUARDED_BY(cs_main);
    std::set<uint256> m_needed GUARDED_BY(cs_main);
    size_t m_bytes GUARDED_BY(cs_main){0};
    size_t m_cache_bytes GUARDED_BY(cs_main){0};
    size_t m_pending_bytes GUARDED_BY(cs_main){0};
    size_t m_template_bytes GUARDED_BY(cs_main){0};
    uint64_t m_revision GUARDED_BY(cs_main){0};
    uint64_t m_clock GUARDED_BY(cs_main){0};
    void Cache(const uint256& hash, std::shared_ptr<const std::vector<unsigned char>> bytes) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void Quarantine(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void IndexTemplates(const uint256& hash, const hashonly::Snapshot& snapshot) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

public:
    explicit HashSnapshotStore(const fs::path& path, bool memory_only = false);
    bool Has(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::optional<std::vector<unsigned char>> Get(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::shared_ptr<const std::vector<unsigned char>> GetShared(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::shared_ptr<const hashonly::Snapshot> Lookup(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    uint256 Put(Span<const unsigned char> raw, std::optional<uint256> expected = std::nullopt) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::vector<uint256> Inventory() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::vector<uint256> Needed() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void Need(const std::vector<uint256>& hashes) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    uint64_t Revision() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_revision; }
    size_t Bytes() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_bytes; }
    size_t Count() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_sizes.size() - m_quarantined.size(); }
    size_t TemplateBytes() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_template_bytes; }
    size_t TemplateCount() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_template_sizes.size() - m_quarantined_templates.size(); }
    void RememberTemplate(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::shared_ptr<const CBlock> Template(const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::optional<CAmount> NativeValidated(const uint256& id) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void SetNativeValidated(const uint256& id, CAmount reward) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool QueueBlock(std::shared_ptr<const CBlock> block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void RemoveBlock(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::vector<std::shared_ptr<const CBlock>> PendingBlocks() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
};
} // namespace sharepool
#endif
