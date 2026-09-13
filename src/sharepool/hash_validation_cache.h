// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHAREPOOL_HASH_VALIDATION_CACHE_H
#define BITCOIN_SHAREPOOL_HASH_VALIDATION_CACHE_H

#include <consensus/sharepool_hash.h>
#include <core_memusage.h>
#include <hash.h>
#include <primitives/block.h>

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>

namespace sharepool {
/** Local decoded-snapshot retention charge, not a consensus or wire limit.
 * Count nested vectors/scripts/witnesses, full reconstructed shares and each
 * distinct immutable transaction allocation once. Cross-entry sharing may be
 * charged again deliberately. Core memory estimates include allocation
 * overhead; this remains cache accounting, not a whole-process RSS limit. */
inline size_t DecodedSnapshotCacheCharge(const hashonly::Snapshot& snapshot, size_t encoded_bytes)
{
    size_t charge{encoded_bytes};
    const auto add = [&](size_t bytes) {
        const auto maximum = std::numeric_limits<size_t>::max();
        charge = bytes > maximum - charge ? maximum : charge + bytes;
    };
    // Charge the owning object, shared counter and conservative tree-entry
    // metadata. std::make_shared may combine allocations; double charge is safe.
    add(memusage::MallocUsage(sizeof(hashonly::Snapshot)));
    add(memusage::MallocUsage(sizeof(memusage::stl_shared_counter)));
    add(memusage::MallocUsage(sizeof(uint256) + sizeof(std::shared_ptr<const hashonly::Snapshot>) +
                             sizeof(size_t) + sizeof(uint64_t) + 4 * sizeof(void*)));
    add(memusage::DynamicUsage(snapshot.binding.payout_script));
    add(memusage::DynamicUsage(snapshot.templates));
    add(memusage::DynamicUsage(snapshot.shares));
    add(memusage::DynamicUsage(snapshot.post_state));
    add(memusage::DynamicUsage(snapshot.payouts));
    add(memusage::DynamicUsage(snapshot.pending));
    add(memusage::DynamicUsage(snapshot.settled));
    add(memusage::DynamicUsage(snapshot.certificates));
    for (const auto& share : snapshot.shares) add(memusage::DynamicUsage(share.origin.payout_script));
    for (const auto& payout : snapshot.payouts) add(RecursiveDynamicUsage(payout));
    for (const auto& credit : snapshot.pending) add(memusage::DynamicUsage(credit.payout_script));
    for (const auto& credit : snapshot.settled) add(memusage::DynamicUsage(credit.payout_script));
    std::set<const CTransaction*> transactions;
    for (const auto& record : snapshot.templates) {
        add(memusage::DynamicUsage(record.block.vtx));
        for (const auto& tx : record.block.vtx) if (tx && transactions.insert(tx.get()).second) {
            add(memusage::DynamicUsage(tx));
            add(RecursiveDynamicUsage(*tx));
        }
    }
    return charge;
}

/** Per-validation-session LRU. Eviction cannot hide available evidence: the
 * caller returns a newly decoded value even when it is too large to retain.
 * Hash/content authentication and dependency budgets belong to the verifier. */
class DecodedSnapshotCache {
    struct Entry {
        std::shared_ptr<const hashonly::Snapshot> snapshot;
        size_t charge;
        uint64_t touched;
    };
    const size_t m_maximum;
    std::map<uint256, Entry> m_entries;
    size_t m_bytes{0};
    uint64_t m_clock{0};
public:
    explicit DecodedSnapshotCache(size_t maximum) : m_maximum{maximum} {}
    std::shared_ptr<const hashonly::Snapshot> Get(const uint256& hash)
    {
        const auto found = m_entries.find(hash);
        if (found == m_entries.end()) return {};
        found->second.touched = ++m_clock;
        return found->second.snapshot;
    }
    bool Put(const uint256& hash, std::shared_ptr<const hashonly::Snapshot> snapshot, size_t encoded_bytes)
    {
        if (!snapshot) return false;
        const auto charge = DecodedSnapshotCacheCharge(*snapshot, encoded_bytes);
        if (charge > m_maximum) return false;
        if (const auto existing = m_entries.find(hash); existing != m_entries.end()) {
            m_bytes -= existing->second.charge;
            m_entries.erase(existing);
        }
        while (charge > m_maximum - m_bytes) {
            const auto oldest = std::min_element(m_entries.begin(), m_entries.end(),
                [](const auto& a, const auto& b) { return a.second.touched < b.second.touched; });
            m_bytes -= oldest->second.charge;
            m_entries.erase(oldest);
        }
        // Publish the charge only after allocation succeeds. A local
        // allocation failure may be caught as MissingData by the verifier.
        m_entries.emplace(hash, Entry{std::move(snapshot), charge, ++m_clock});
        m_bytes += charge;
        return true;
    }
    size_t Bytes() const { return m_bytes; }
    size_t Size() const { return m_entries.size(); }
};

/** Process-local native-validation identity; never a consensus commitment.
 *
 * The exact, unnormalized header binds its parent and every search field. The
 * ordered witness transaction IDs bind each immutable transaction, including
 * coinbase and witness bytes. A hit still requires the caller's native context
 * checks. Reusing cached transaction hashes avoids hashing full shared payloads
 * again on every cache lookup. No body validity is inferred from these hashes.
 */
inline uint256 NativeBodyCacheKey(const CBlock& block)
{
    static constexpr char domain[]{"SharePool/native-body-cache/v1"};
    HashWriter writer;
    writer.write(AsBytes(Span{domain}));
    writer << block.GetBlockHeader();
    WriteCompactSize(writer, block.vtx.size());
    for (const auto& tx : block.vtx) {
        if (!tx) throw std::invalid_argument("null transaction in native body cache key");
        writer << tx->GetWitnessHash();
    }
    return writer.GetHash();
}
} // namespace sharepool

#endif // BITCOIN_SHAREPOOL_HASH_VALIDATION_CACHE_H
