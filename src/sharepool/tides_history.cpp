// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/tides_history.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/sharepool.h>
#include <hash.h>

#include <algorithm>
#include <charconv>
#include <iterator>
#include <limits>
#include <mutex>
#include <type_traits>

namespace sharepool::tides {
namespace {
std::mutex g_cache_budget_mutex;
HistoryCacheBudget g_cache_budget;

void CheckCacheBudget(const HistoryCacheBudget& budget)
{
    if (!budget.queries || !budget.query_bytes) throw std::invalid_argument("TIDES history query cache needs a positive local budget");
}

size_t ParseMiB(std::string_view text, const char* option)
{
    constexpr size_t MIB{1024 * 1024};
    const auto invalid = [&]() {
        return std::invalid_argument(std::string{option} + " requires a positive whole MiB value that fits the platform byte size");
    };
    if (text.empty()) throw invalid();
    size_t value{0};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() ||
        value == 0 || value > std::numeric_limits<size_t>::max() / MIB) {
        throw invalid();
    }
    return value * MIB;
}

Work Numeric(const uint256& value)
{
    Work result{0};
    for (size_t i{value.size()}; i > 0; --i) {
        result <<= 8;
        result += value.begin()[i - 1];
    }
    return result;
}

size_t EntryBytes(const Admission& entry)
{
    // Charge the object as well as the separately allocated script. Cache
    // limits bound derived summaries; the native store owns source snapshots.
    return sizeof(Admission) + entry.payout_script.size();
}

bool AnchorMatches(const HistoryDelta& delta, const CBlockIndex& index)
{
    return index.pprev && index.nHeight > 0 && index.pprev->nHeight == index.nHeight - 1 &&
        delta.block_hash == index.GetBlockHash() && delta.parent_hash == index.pprev->GetBlockHash() &&
        delta.snapshot_hash == index.m_mm_rhs && delta.height == uint32_t(index.nHeight);
}

uint256 QueryId(const CBlockIndex& index, uint32_t activation, const uint256& pool, const Work& required)
{
    HashWriter writer;
    writer << std::string{"SharePool/tides-history/query/v1"} << index.GetBlockHash()
           << index.nHeight << index.m_mm_rhs << (index.pprev ? index.pprev->GetBlockHash() : uint256{})
           << activation << pool << required.str();
    return writer.GetHash();
}
} // namespace

HistoryCacheBudget HistoryCacheBudgetFromMiB(std::string_view cache_mib, std::string_view query_mib)
{
    HistoryCacheBudget result;
    result.bytes = ParseMiB(cache_mib, "-sharepooltideshistorycachemib");
    result.query_bytes = ParseMiB(query_mib, "-sharepooltideshistoryquerymib");
    return result;
}

void ConfigureHistoryCache(HistoryCacheBudget budget)
{
    CheckCacheBudget(budget);
    const std::lock_guard lock{g_cache_budget_mutex};
    g_cache_budget = budget;
}

HistoryCacheBudget ConfiguredHistoryCacheBudget()
{
    const std::lock_guard lock{g_cache_budget_mutex};
    return g_cache_budget;
}

DeltaResult DeltaResult::Ready(std::shared_ptr<const HistoryDelta> value)
{
    return {HistoryStatus::Ready, std::move(value), {}, {}};
}
DeltaResult DeltaResult::Missing(std::vector<uint256> hashes, std::string reason)
{
    return {HistoryStatus::MissingData, {}, std::move(hashes), std::move(reason)};
}
DeltaResult DeltaResult::Invalid(std::string reason)
{
    return {HistoryStatus::Invalid, {}, {}, std::move(reason)};
}
DeltaResult DeltaResult::Limited(std::string reason)
{
    return {HistoryStatus::ResourceLimit, {}, {}, std::move(reason)};
}

struct HistoryIndex::Impl {
    struct CachedDelta {
        std::shared_ptr<const HistoryDelta> value;
        size_t bytes;
        uint64_t touched;
    };
    struct Query {
        uint32_t next_height;
        uint256 next_hash;
        Work remaining;
        std::vector<Admission> reverse{};
        size_t bytes{0};
        bool complete{false};
        bool to_activation{false};
        uint64_t touched{0};
    };
    HistoryCacheBudget budget;
    std::map<uint256, CachedDelta> deltas;
    std::map<uint256, Query> queries;
    size_t delta_bytes{0};
    size_t query_bytes{0};
    uint64_t clock{0};

    explicit Impl(HistoryCacheBudget value) : budget{value} {}

    void EraseQuery(std::map<uint256, Query>::iterator it)
    {
        query_bytes -= it->second.bytes;
        queries.erase(it);
    }

    bool MakeQuerySpace(size_t extra, const uint256& keep)
    {
        if (extra > budget.query_bytes || queries.at(keep).bytes > budget.query_bytes - extra) return false;
        while (query_bytes > budget.query_bytes - extra) {
            auto oldest = queries.end();
            for (auto it = queries.begin(); it != queries.end(); ++it) {
                if (it->first != keep && (oldest == queries.end() || it->second.touched < oldest->second.touched)) oldest = it;
            }
            if (oldest == queries.end()) return false;
            EraseQuery(oldest);
        }
        return true;
    }

    void Cache(const uint256& id, std::shared_ptr<const HistoryDelta> value, size_t bytes)
    {
        if (!budget.blocks || bytes > budget.bytes) return;
        while (!deltas.empty() && (deltas.size() >= budget.blocks || delta_bytes > budget.bytes - bytes)) {
            const auto oldest = std::min_element(deltas.begin(), deltas.end(),
                [](const auto& a, const auto& b) { return a.second.touched < b.second.touched; });
            delta_bytes -= oldest->second.bytes;
            deltas.erase(oldest);
        }
        deltas.emplace(id, CachedDelta{std::move(value), bytes, ++clock});
        delta_bytes += bytes;
    }
};

HistoryIndex::HistoryIndex(HistoryCacheBudget budget) : m_impl{std::make_unique<Impl>(budget)}
{
    CheckCacheBudget(budget);
}
HistoryIndex::~HistoryIndex() = default;
void HistoryIndex::Clear()
{
    m_impl = std::make_unique<Impl>(m_impl->budget);
}

void HistoryIndex::SetCacheBudget(HistoryCacheBudget budget)
{
    CheckCacheBudget(budget);
    auto& impl = *m_impl;
    if (impl.budget == budget) return;
    impl.budget = budget;
    while (!impl.deltas.empty() && (impl.deltas.size() > budget.blocks || impl.delta_bytes > budget.bytes)) {
        const auto oldest = std::min_element(impl.deltas.begin(), impl.deltas.end(),
            [](const auto& a, const auto& b) { return a.second.touched < b.second.touched; });
        impl.delta_bytes -= oldest->second.bytes;
        impl.deltas.erase(oldest);
    }
    while (!impl.queries.empty() && (impl.queries.size() > budget.queries || impl.query_bytes > budget.query_bytes)) {
        const auto oldest = std::min_element(impl.queries.begin(), impl.queries.end(),
            [](const auto& a, const auto& b) { return a.second.touched < b.second.touched; });
        impl.EraseQuery(oldest);
    }
}

HistoryWindow HistoryIndex::ReadPool(const CBlockIndex* previous, uint32_t activation_height,
                                    const uint256& pool, const Work& required_work,
                                    const FetchHistoryDelta& fetch, HistoryBudget budget)
{
    HistoryWindow result;
    const auto fail = [&](HistoryStatus status, std::string reason, std::vector<uint256> missing = {}) {
        result.status = status;
        result.reason = std::move(reason);
        result.missing = std::move(missing);
        result.entries.clear();
        result.complete_to_activation = false;
        return result;
    };
    if (!activation_height || pool.IsNull() || !fetch) {
        return fail(HistoryStatus::Invalid, "tides-history-request");
    }
    if (!previous || previous->nHeight < 0) {
        return fail(HistoryStatus::MissingData, "tides-history-parent-unavailable");
    }
    if (!required_work || uint32_t(previous->nHeight) < activation_height) {
        result.status = HistoryStatus::Ready;
        result.complete_to_activation = uint32_t(previous->nHeight) < activation_height;
        return result;
    }

    auto& impl = *m_impl;
    try {
        const auto query_id = QueryId(*previous, activation_height, pool, required_work);
        auto found = impl.queries.find(query_id);
        if (found == impl.queries.end()) {
            while (impl.queries.size() >= impl.budget.queries) {
                const auto oldest = std::min_element(impl.queries.begin(), impl.queries.end(),
                    [](const auto& a, const auto& b) { return a.second.touched < b.second.touched; });
                impl.EraseQuery(oldest);
            }
            found = impl.queries.emplace(query_id, Impl::Query{uint32_t(previous->nHeight), previous->GetBlockHash(), required_work}).first;
        }
        auto& query = found->second;
        query.touched = ++impl.clock;
        while (!query.complete) {
            if (query.next_height < activation_height) {
                query.complete = query.to_activation = true;
                break;
            }
            if (result.scanned_blocks >= budget.blocks) return fail(HistoryStatus::ResourceLimit, "tides-history-block-budget");
            const auto* ancestor = previous->GetAncestor(query.next_height);
            if (!ancestor || ancestor->GetBlockHash() != query.next_hash) {
                return fail(HistoryStatus::MissingData, "tides-history-ancestry-unavailable");
            }
            const auto& index = *ancestor;
            const auto block_id = index.GetBlockHash();
            std::shared_ptr<const HistoryDelta> delta;
            size_t bytes{0};
            if (const auto cached = impl.deltas.find(block_id); cached != impl.deltas.end()) {
                if (AnchorMatches(*cached->second.value, index)) {
                    delta = cached->second.value;
                    bytes = cached->second.bytes;
                    cached->second.touched = ++impl.clock;
                } else {
                    impl.delta_bytes -= cached->second.bytes;
                    impl.deltas.erase(cached);
                }
            }
            if (!delta) {
                DeltaResult fetched;
                try { fetched = fetch(index); }
                catch (const std::bad_alloc&) { return fail(HistoryStatus::ResourceLimit, "tides-history-local-allocation"); }
                catch (const std::exception&) { return fail(HistoryStatus::MissingData, "tides-history-local-read", {index.m_mm_rhs}); }
                if (fetched.status != HistoryStatus::Ready) {
                    if (fetched.status == HistoryStatus::MissingData && fetched.missing.empty()) fetched.missing.push_back(index.m_mm_rhs);
                    return fail(fetched.status, std::move(fetched.reason), std::move(fetched.missing));
                }
                if (!fetched.delta || !fetched.delta->encoded_bytes || !AnchorMatches(*fetched.delta, index)) {
                    return fail(HistoryStatus::MissingData, "tides-history-anchor-mismatch", {index.m_mm_rhs});
                }
                if (fetched.delta->admissions.size() > budget.entries - result.scanned_entries ||
                    fetched.delta->encoded_bytes > budget.bytes - result.scanned_bytes) {
                    return fail(HistoryStatus::ResourceLimit, "tides-history-delta-budget");
                }
                bytes = sizeof(HistoryDelta);
                const Admission* last{nullptr};
                for (const auto& entry : fetched.delta->admissions) {
                    if (entry.proof_id.IsNull() || entry.pool.IsNull() || entry.work.IsNull() ||
                        !IsPayoutScript(entry.payout_script) ||
                        (last && !(UintToArith256(last->proof_id) < UintToArith256(entry.proof_id)))) {
                        return fail(HistoryStatus::Invalid, "tides-history-admission");
                    }
                    const auto charge = EntryBytes(entry);
                    if (charge > std::numeric_limits<size_t>::max() - bytes) return fail(HistoryStatus::ResourceLimit, "tides-history-cache-budget");
                    bytes += charge;
                    last = &entry;
                }
                bytes = std::max(bytes, fetched.delta->encoded_bytes);
                // Own a copy: later changes to the callback's local objects
                // must not mutate previously verified cached admission data.
                delta = std::make_shared<const HistoryDelta>(*fetched.delta);
                impl.Cache(block_id, delta, bytes);
            }
            if (delta->admissions.size() > budget.entries - result.scanned_entries ||
                bytes > budget.bytes - result.scanned_bytes) {
                return fail(HistoryStatus::ResourceLimit, "tides-history-delta-budget");
            }

            std::vector<Admission> selected;
            Work remaining = query.remaining;
            size_t extra{0};
            // A native block supplies no objective per-proof arrival order.
            // Retain its complete pool batch so payout boundary clipping cannot
            // select recipients by proof ID, even when enough work was found.
            for (auto it = delta->admissions.rbegin(); it != delta->admissions.rend(); ++it) {
                if (it->pool != pool) continue;
                const auto charge = EntryBytes(*it);
                if (charge > impl.budget.query_bytes - std::min(extra, impl.budget.query_bytes)) {
                    return fail(HistoryStatus::ResourceLimit, "tides-history-query-budget");
                }
                extra += charge;
                selected.push_back(*it);
                selected.back().admission_height = index.nHeight;
                remaining -= std::min(remaining, Numeric(it->work));
            }
            if (!impl.MakeQuerySpace(extra, query_id)) return fail(HistoryStatus::ResourceLimit, "tides-history-query-budget");
            if (selected.size() > query.reverse.max_size() - query.reverse.size()) return fail(HistoryStatus::ResourceLimit, "tides-history-query-budget");
            // Reserve before changing the cursor. Moving Admission cannot
            // throw, so a failed allocation never advances only half a delta.
            static_assert(std::is_nothrow_move_constructible_v<Admission>);
            query.reverse.reserve(query.reverse.size() + selected.size());
            query.reverse.insert(query.reverse.end(), std::make_move_iterator(selected.begin()), std::make_move_iterator(selected.end()));
            query.bytes += extra;
            impl.query_bytes += extra;
            query.remaining = remaining;
            query.next_height = uint32_t(index.nHeight - 1);
            query.next_hash = index.pprev->GetBlockHash();
            query.complete = remaining == 0;
            ++result.scanned_blocks;
            result.scanned_entries += delta->admissions.size();
            result.scanned_bytes += bytes;
        }
        result.entries.reserve(query.reverse.size());
        for (auto it = query.reverse.rbegin(); it != query.reverse.rend(); ++it) {
            result.entries.push_back({result.entries.size() + 1, it->proof_id, it->pool, it->payout_script, it->work, it->admission_height});
        }
        result.status = HistoryStatus::Ready;
        result.complete_to_activation = query.to_activation;
        return result;
    } catch (const std::bad_alloc&) {
        return fail(HistoryStatus::ResourceLimit, "tides-history-local-allocation");
    } catch (const std::length_error&) {
        return fail(HistoryStatus::ResourceLimit, "tides-history-local-allocation");
    }
}
} // namespace sharepool::tides
