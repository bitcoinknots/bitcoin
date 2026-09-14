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
#include <atomic>
#include <cassert>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>

namespace sharepool {
/** Local optional retention policy, independent of consensus and RPC concurrency. */
inline constexpr size_t DEFAULT_DECODED_SNAPSHOT_RETENTION_BYTES{128 * 1024 * 1024};

/** Shared accounting for optional decoded LRU entries, not all live snapshots.
 * Reservations never wait for capacity. Leases keep the counter alive beyond
 * the service owner and release it without I/O, callbacks or chain locks. */
class DecodedSnapshotRetentionBudget {
    struct State {
        const size_t maximum;
        std::atomic<size_t> bytes{0};
        explicit State(size_t limit) : maximum{limit} {}
    };
    const std::shared_ptr<State> m_state;
public:
    class Lease {
        friend class DecodedSnapshotRetentionBudget;
        std::shared_ptr<State> m_state;
        size_t m_bytes{0};
        Lease(std::shared_ptr<State> state, size_t bytes) noexcept : m_state{std::move(state)}, m_bytes{bytes} {}
        void Release() noexcept
        {
            if (m_state) {
                [[maybe_unused]] const auto prior = m_state->bytes.fetch_sub(m_bytes, std::memory_order_relaxed);
                assert(prior >= m_bytes);
                m_state.reset();
            }
        }
    public:
        Lease() = default;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept : m_state{std::move(other.m_state)}, m_bytes{other.m_bytes} {}
        Lease& operator=(Lease&& other) noexcept
        {
            if (this != &other) {
                Release();
                m_state = std::move(other.m_state);
                m_bytes = other.m_bytes;
            }
            return *this;
        }
        ~Lease() { Release(); }
    };

    explicit DecodedSnapshotRetentionBudget(size_t maximum) : m_state{std::make_shared<State>(maximum)} {}
    std::optional<Lease> TryAcquire(size_t bytes)
    {
        size_t current = m_state->bytes.load(std::memory_order_relaxed);
        do {
            if (bytes > m_state->maximum - current) return std::nullopt;
        } while (!m_state->bytes.compare_exchange_weak(current, current + bytes, std::memory_order_relaxed));
        return Lease{m_state, bytes};
    }
    size_t Bytes() const { return m_state->bytes.load(std::memory_order_relaxed); }
};

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
                             sizeof(size_t) + sizeof(uint64_t) + sizeof(DecodedSnapshotRetentionBudget::Lease) + 4 * sizeof(void*)));
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
        // Destroy the reservation after releasing this entry's snapshot owner.
        DecodedSnapshotRetentionBudget::Lease lease;
        std::shared_ptr<const hashonly::Snapshot> snapshot;
        size_t charge;
        uint64_t touched;
    };
    const size_t m_maximum;
    const size_t m_maximum_entries;
    const std::shared_ptr<DecodedSnapshotRetentionBudget> m_budget;
    std::map<uint256, Entry> m_entries;
    size_t m_bytes{0};
    uint64_t m_clock{0};
public:
    explicit DecodedSnapshotCache(size_t maximum, size_t maximum_entries = 1024,
                                  std::shared_ptr<DecodedSnapshotRetentionBudget> budget = {})
        : m_maximum{maximum}, m_maximum_entries{maximum_entries}, m_budget{std::move(budget)} {}
    DecodedSnapshotCache(const DecodedSnapshotCache&) = delete;
    DecodedSnapshotCache& operator=(const DecodedSnapshotCache&) = delete;
    std::shared_ptr<const hashonly::Snapshot> Get(const uint256& hash)
    {
        const auto found = m_entries.find(hash);
        if (found == m_entries.end()) return {};
        found->second.touched = ++m_clock;
        return found->second.snapshot;
    }
    bool Put(const uint256& hash, std::shared_ptr<const hashonly::Snapshot> snapshot, size_t encoded_bytes) try
    {
        if (!snapshot || m_maximum_entries == 0) return false;
        const auto charge = DecodedSnapshotCacheCharge(*snapshot, encoded_bytes);
        if (charge > m_maximum) return false;
        if (const auto existing = m_entries.find(hash); existing != m_entries.end()) {
            m_bytes -= existing->second.charge;
            m_entries.erase(existing);
        }
        while (charge > m_maximum - m_bytes || m_entries.size() >= m_maximum_entries) {
            const auto oldest = std::min_element(m_entries.begin(), m_entries.end(),
                [](const auto& a, const auto& b) { return a.second.touched < b.second.touched; });
            m_bytes -= oldest->second.charge;
            m_entries.erase(oldest);
        }
        DecodedSnapshotRetentionBudget::Lease lease;
        if (m_budget) {
            auto reservation = m_budget->TryAcquire(charge);
            if (!reservation) return false;
            lease = std::move(*reservation);
        }
        // Publish the local charge only after allocation succeeds. The lease
        // releases the shared charge if insertion throws. A caller may still
        // own the snapshot after eviction, outside optional LRU accounting.
        m_entries.emplace(hash, Entry{std::move(lease), std::move(snapshot), charge, ++m_clock});
        m_bytes += charge;
        return true;
    } catch (const std::bad_alloc&) {
        // Failure to retain optional evidence must not hide an available value.
        return false;
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
