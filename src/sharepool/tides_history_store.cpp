// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/tides_history_store.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/sharepool.h>
#include <crypto/hmac_sha256.h>
#include <dbwrapper.h>
#include <hash.h>
#include <kernel/cs_main.h>
#include <random.h>
#include <support/cleanse.h>
#include <util/fs_helpers.h>
#include <util/readwritefile.h>

#include <algorithm>
#include <limits>
#include <map>
#include <mutex>
#include <set>

namespace sharepool::tides {
namespace {
constexpr uint32_t FORMAT{1};
constexpr uint64_t RECORD_ALLOWANCE{64};
struct LocalFailure : std::runtime_error { using std::runtime_error::runtime_error; };
struct LocalLimit : std::runtime_error { using std::runtime_error::runtime_error; };

template <typename T> uint256 ContentHash(const char* domain, const T& value)
{
    HashWriter writer;
    writer << std::string{domain} << value;
    return writer.GetHash();
}

uint256 ScopeId(const PersistentHistoryIndex::Scope& scope)
{
    HashWriter writer;
    writer << std::string{"SharePool/local-history/scope/v1"} << FORMAT
           << scope.genesis << scope.rules << scope.profile << scope.activation_height;
    return writer.GetHash();
}

uint256 Seal(const uint256& key, const uint256& scope, const uint256& digest)
{
    uint256 result;
    CHMAC_SHA256(key.begin(), key.size()).Write(scope.begin(), scope.size())
        .Write(digest.begin(), digest.size()).Finalize(result.begin());
    return result;
}

uint256 LoadKey(const fs::path& path, bool memory_only, bool rebuild)
{
    uint256 key;
    if (memory_only) {
        GetStrongRandBytes({key.begin(), key.size()});
        return key;
    }
    fs::create_directories(path);
    const auto key_path = path / "seal.key";
    if (!rebuild && fs::exists(key_path)) {
#ifndef WIN32
        constexpr auto exposed = fs::perms::group_all | fs::perms::others_all;
        if ((fs::status(key_path).permissions() & exposed) != fs::perms::none) {
            throw LocalFailure("tides-history-index-key-permissions");
        }
#endif
        const auto [ok, bytes] = ReadBinaryFile(key_path, key.size() + 1);
        if (!ok || bytes.size() != key.size()) throw LocalFailure("tides-history-index-key-unreadable");
        std::copy(bytes.begin(), bytes.end(), key.begin());
        if (key.IsNull()) throw LocalFailure("tides-history-index-key-unreadable");
        return key;
    }
    // A newly generated key must never authenticate pre-existing coverage.
    if (!rebuild && fs::exists(path / "index")) throw LocalFailure("tides-history-index-key-missing-rebuild-required");
    GetStrongRandBytes({key.begin(), key.size()});
    const auto temporary = path / "seal.key.new";
    FILE* file = fsbridge::fopen(temporary, "wb");
    if (!file) throw LocalFailure("tides-history-index-key-create");
    bool written{false};
    try {
#ifndef WIN32
        fs::permissions(temporary, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
#endif
        written = std::fwrite(key.begin(), 1, key.size(), file) == key.size() && FileCommit(file);
    } catch (...) {
        std::fclose(file);
        throw;
    }
    if (std::fclose(file) != 0 || !written || !RenameOver(temporary, key_path)) {
        throw LocalFailure("tides-history-index-key-commit");
    }
    DirectoryCommit(path);
    return key;
}

struct MapNode {
    uint8_t kind{0}; // 1 leaf; 2 branch. Branch bits strictly increase down a path.
    uint16_t bit{0};
    uint256 pool;
    uint256 value;
    uint256 left;
    uint256 right;
    SERIALIZE_METHODS(MapNode, obj)
    {
        READWRITE(obj.kind);
        if (obj.kind == 1) READWRITE(obj.pool, obj.value);
        else if (obj.kind == 2) READWRITE(obj.bit, obj.left, obj.right);
        else throw std::ios_base::failure("history map node type");
    }
    uint256 Id() const { return ContentHash("SharePool/local-history/map/v1", *this); }
    bool Valid() const
    {
        return kind == 1 ? !pool.IsNull() && !value.IsNull() :
            kind == 2 && bit < 256 && !left.IsNull() && !right.IsNull() && left != right;
    }
};

bool Bit(const uint256& key, uint16_t bit) { return (key.begin()[bit / 8] >> (7 - bit % 8)) & 1; }
uint16_t Difference(const uint256& a, const uint256& b)
{
    for (uint16_t bit{0}; bit < 256; ++bit) if (Bit(a, bit) != Bit(b, bit)) return bit;
    return 256;
}

struct PoolBatch {
    uint256 block;
    uint256 parent;
    uint256 snapshot;
    uint32_t height{0};
    uint256 pool;
    uint256 prior;
    uint64_t count{0};
    uint256 admissions;
    SERIALIZE_METHODS(PoolBatch, obj)
    {
        READWRITE(obj.block, obj.parent, obj.snapshot, obj.height, obj.pool, obj.prior, obj.count, obj.admissions);
    }
    uint256 Id() const { return ContentHash("SharePool/local-history/batch/v1", *this); }
};

struct Coverage {
    uint256 block;
    uint256 parent;
    uint256 snapshot;
    uint32_t height{0};
    uint256 parent_root;
    uint256 root;
    uint256 seal;
    SERIALIZE_METHODS(Coverage, obj)
    {
        READWRITE(obj.block, obj.parent, obj.snapshot, obj.height, obj.parent_root, obj.root, obj.seal);
    }
    uint256 Digest() const
    {
        auto copy = *this;
        copy.seal.SetNull();
        return ContentHash("SharePool/local-history/coverage/v1", copy);
    }
};

struct Metadata {
    uint32_t format{FORMAT};
    uint256 scope;
    uint64_t blocks{0};
    uint64_t batches{0};
    uint64_t nodes{0};
    uint64_t charged{0};
    uint256 seal;
    SERIALIZE_METHODS(Metadata, obj)
    {
        READWRITE(obj.format, obj.scope, obj.blocks, obj.batches, obj.nodes, obj.charged, obj.seal);
    }
    uint256 Digest() const
    {
        auto copy = *this;
        copy.seal.SetNull();
        return ContentHash("SharePool/local-history/metadata/v1", copy);
    }
};

bool Matches(const HistoryDelta& delta, const CBlockIndex& index)
{
    return index.pprev && index.nHeight > 0 && delta.encoded_bytes &&
        delta.block_hash == index.GetBlockHash() && delta.parent_hash == index.pprev->GetBlockHash() &&
        delta.snapshot_hash == index.m_mm_rhs && delta.height == uint32_t(index.nHeight);
}

bool ValidAdmissions(const std::vector<Admission>& admissions)
{
    const Admission* previous{nullptr};
    for (const auto& entry : admissions) {
        if (entry.proof_id.IsNull() || entry.pool.IsNull() || entry.work.IsNull() || !IsPayoutScript(entry.payout_script) ||
            (previous && !(UintToArith256(previous->proof_id) < UintToArith256(entry.proof_id)))) return false;
        previous = &entry;
    }
    return true;
}

uint256 AdmissionsHash(const std::vector<Admission>& entries)
{
    HashWriter writer;
    writer << std::string{"SharePool/local-history/admissions/v1"} << uint64_t(entries.size());
    for (const auto& entry : entries) writer << entry.proof_id << entry.pool << entry.payout_script << entry.work;
    return writer.GetHash();
}

Work Numeric(const uint256& value)
{
    Work result{0};
    for (size_t i{value.size()}; i > 0; --i) { result <<= 8; result += value.begin()[i - 1]; }
    return result;
}

bool NativeValidated(const CBlockIndex& index)
{
    // This helper is called only with the index mutex released. Workers may
    // arrive without cs_main, while RPC callers may already own its recursive lock.
    LOCK(cs_main);
    return index.IsValid(BLOCK_VALID_SCRIPTS);
}
} // namespace

struct PersistentHistoryIndex::Impl {
    struct Query {
        uint256 next;
        uint32_t before_height{0};
        Work remaining;
        std::vector<Admission> reverse;
        size_t bytes{0};
        uint64_t touched{0};
        bool complete{false};
        bool to_activation{false};
    };
    const Scope scope;
    const uint256 scope_id;
    uint256 key;
    const Options options;
    CDBWrapper db;
    mutable std::mutex mutex;
    Metadata metadata;
    std::map<uint256, std::shared_ptr<Query>> queries;
    size_t query_bytes{0};
    uint64_t clock{0};
    bool disk_full{false};

    Impl(const fs::path& path, Scope chosen, Options config, bool memory_only)
        : scope{chosen}, scope_id{ScopeId(chosen)}, key{LoadKey(path, memory_only, config.rebuild)}, options{config},
          db{DBParams{.path = path / "index", .cache_bytes = config.cache_bytes,
                      .memory_only = memory_only, .wipe_data = config.rebuild}}
    {
        if (db.Exists(uint8_t{'M'})) {
            if (!db.Read(uint8_t{'M'}, metadata) || metadata.format != FORMAT || metadata.scope != scope_id ||
                metadata.seal != Seal(key, scope_id, metadata.Digest())) throw LocalFailure("tides-history-index-metadata-unavailable");
        } else {
            if (!db.IsEmpty()) throw LocalFailure("tides-history-index-metadata-missing");
            metadata.scope = scope_id;
            metadata.charged = 1 + GetSerializeSize(metadata) + RECORD_ALLOWANCE;
            metadata.seal = Seal(key, scope_id, metadata.Digest());
            if (metadata.charged > options.max_bytes) throw LocalLimit("tides-history-index-disk-budget");
            if (!db.Write(uint8_t{'M'}, metadata, true)) throw LocalFailure("tides-history-index-write");
        }
    }
    ~Impl() { memory_cleanse(key.begin(), key.size()); }

    std::optional<Coverage> Covered(const CBlockIndex& index)
    {
        const auto id = std::pair{uint8_t{'C'}, index.GetBlockHash()};
        Coverage value;
        if (!db.Exists(id)) return {};
        if (!db.Read(id, value) || !index.pprev || value.block != index.GetBlockHash() ||
            value.parent != index.pprev->GetBlockHash() || value.snapshot != index.m_mm_rhs ||
            value.height != uint32_t(index.nHeight) || value.seal != Seal(key, scope_id, value.Digest())) {
            throw LocalFailure("tides-history-index-coverage-unavailable");
        }
        return value;
    }

    MapNode Node(const uint256& id, const std::map<uint256, MapNode>& staged = {})
    {
        if (const auto it = staged.find(id); it != staged.end()) return it->second;
        MapNode node;
        if (!db.Read(std::pair{uint8_t{'N'}, id}, node) || !node.Valid() || node.Id() != id) {
            throw LocalFailure("tides-history-index-map-unavailable");
        }
        return node;
    }

    uint256 Find(const uint256& root, const uint256& pool, const std::map<uint256, MapNode>& staged = {})
    {
        auto cursor = root;
        int previous_bit{-1};
        while (!cursor.IsNull()) {
            const auto node = Node(cursor, staged);
            if (node.kind == 1) return node.pool == pool ? node.value : uint256{};
            if (node.bit <= previous_bit) throw LocalFailure("tides-history-index-map-order");
            previous_bit = node.bit;
            cursor = Bit(pool, node.bit) ? node.right : node.left;
        }
        return {};
    }

    uint256 Set(const uint256& root, const uint256& pool, const uint256& value, std::map<uint256, MapNode>& staged)
    {
        MapNode leaf;
        leaf.kind = 1;
        leaf.pool = pool;
        leaf.value = value;
        const auto leaf_id = leaf.Id();
        staged.emplace(leaf_id, leaf);
        if (root.IsNull()) return leaf_id;
        auto cursor = root;
        int previous_bit{-1};
        while (true) {
            const auto node = Node(cursor, staged);
            if (node.kind == 1) {
                const auto difference = Difference(pool, node.pool);
                const auto replace = [&](const auto& self, const uint256& id, int prior_bit) -> uint256 {
                    const auto original = Node(id, staged);
                    if (original.kind == 2 && original.bit <= prior_bit) throw LocalFailure("tides-history-index-map-order");
                    if (original.kind == 2 && original.bit < difference) {
                        auto changed = original;
                        if (Bit(pool, changed.bit)) changed.right = self(self, changed.right, changed.bit);
                        else changed.left = self(self, changed.left, changed.bit);
                        const auto result = changed.Id();
                        staged.emplace(result, changed);
                        return result;
                    }
                    if (difference == 256) {
                        if (original.kind != 1 || original.pool != pool) throw LocalFailure("tides-history-index-map-shape");
                        return leaf_id;
                    }
                    MapNode branch;
                    branch.kind = 2;
                    branch.bit = difference;
                    branch.left = Bit(pool, difference) ? id : leaf_id;
                    branch.right = Bit(pool, difference) ? leaf_id : id;
                    const auto result = branch.Id();
                    staged.emplace(result, branch);
                    return result;
                };
                return replace(replace, root, -1);
            }
            if (node.bit <= previous_bit) throw LocalFailure("tides-history-index-map-order");
            previous_bit = node.bit;
            cursor = Bit(pool, node.bit) ? node.right : node.left;
        }
    }

    Coverage Add(const HistoryDelta& delta, const uint256& parent_root, size_t batch_budget)
    {
        std::map<uint256, std::vector<Admission>> pools;
        for (const auto& entry : delta.admissions) pools[entry.pool].push_back(entry);
        std::map<uint256, MapNode> nodes;
        std::map<uint256, PoolBatch> batches;
        auto root = parent_root;
        for (const auto& [pool, entries] : pools) {
            PoolBatch record{delta.block_hash, delta.parent_hash, delta.snapshot_hash, delta.height, pool,
                             Find(parent_root, pool), entries.size(), AdmissionsHash(entries)};
            const auto id = record.Id();
            batches.emplace(id, record);
            root = Set(root, pool, id, nodes);
            // Bound intermediate path copying before constructing the durable batch.
            if (nodes.size() > batch_budget / (sizeof(MapNode) + RECORD_ALLOWANCE)) {
                throw LocalLimit("tides-history-index-batch-budget");
            }
        }
        Coverage covered{delta.block_hash, delta.parent_hash, delta.snapshot_hash, delta.height, parent_root, root, {}};
        covered.seal = Seal(key, scope_id, covered.Digest());
        // Inserting several pools may create intermediate roots that no
        // covered native block references. Do not retain those dead paths.
        std::set<uint256> live;
        const auto retain = [&](const auto& self, const uint256& id) -> void {
            const auto it = nodes.find(id);
            if (it == nodes.end() || !live.insert(id).second) return;
            if (it->second.kind == 2) { self(self, it->second.left); self(self, it->second.right); }
        };
        retain(retain, root);
        CDBBatch write{db};
        auto next = metadata;
        const auto append = [&](const auto& id, const auto& value) {
            const uint64_t charge = GetSerializeSize(id) + GetSerializeSize(value) + RECORD_ALLOWANCE;
            if (charge > options.max_bytes - std::min(options.max_bytes, next.charged)) {
                // The quota is fixed for this instance. Continue serving
                // already-covered roots but do not repeatedly fetch a whole
                // new snapshot just to rediscover that it cannot be indexed.
                disk_full = true;
                throw LocalLimit("tides-history-index-disk-budget");
            }
            next.charged += charge;
            write.Write(id, value);
            if (write.SizeEstimate() > batch_budget) throw LocalLimit("tides-history-index-batch-budget");
        };
        for (const auto& [id, node] : nodes) {
            if (!live.contains(id)) continue;
            if (db.Exists(std::pair{uint8_t{'N'}, id})) { (void)Node(id); continue; }
            append(std::pair{uint8_t{'N'}, id}, node);
            ++next.nodes;
        }
        for (const auto& [id, record] : batches) { append(std::pair{uint8_t{'B'}, id}, record); ++next.batches; }
        append(std::pair{uint8_t{'C'}, delta.block_hash}, covered);
        ++next.blocks;
        next.seal = Seal(key, scope_id, next.Digest());
        write.Write(uint8_t{'M'}, next);
        if (write.SizeEstimate() > batch_budget) throw LocalLimit("tides-history-index-batch-budget");
        if (!db.WriteBatch(write, true)) throw LocalFailure("tides-history-index-write");
        metadata = next;
        return covered;
    }

    bool Evict(const std::shared_ptr<Query>& keep = {})
    {
        auto oldest = queries.end();
        for (auto it = queries.begin(); it != queries.end(); ++it) {
            if (it->second == keep || it->second.use_count() != 1) continue;
            if (oldest == queries.end() || it->second->touched < oldest->second->touched) oldest = it;
        }
        if (oldest == queries.end()) return false;
        query_bytes -= oldest->second->bytes;
        queries.erase(oldest);
        return true;
    }
};

PersistentHistoryIndex::PersistentHistoryIndex(const fs::path& path, Scope scope, Options options, bool memory_only)
{
    // Invalid local options cannot create keys or wipe a previously useful index.
    if (scope.genesis.IsNull() || scope.rules.IsNull() || !scope.profile || !scope.activation_height ||
        !options.max_bytes || !options.cache_bytes) throw std::invalid_argument("tides history scope and budgets must be positive");
    m_impl = std::make_unique<Impl>(path, scope, options, memory_only);
}
PersistentHistoryIndex::~PersistentHistoryIndex() = default;

bool PersistentHistoryIndex::MatchesScope(const uint256& genesis, const uint256& rules, uint32_t profile, uint32_t activation_height) const
{
    return m_impl->scope == Scope{genesis, rules, profile, activation_height};
}

PersistentHistoryIndex::Stats PersistentHistoryIndex::GetStats() const
{
    const std::lock_guard lock{m_impl->mutex};
    const auto& meta = m_impl->metadata;
    return {meta.blocks, meta.batches, meta.nodes, meta.charged};
}

HistoryWindow PersistentHistoryIndex::ReadPool(const CBlockIndex* previous, uint32_t activation_height,
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
    auto& impl = *m_impl;
    if (!previous || previous->nHeight < 0 || activation_height != impl.scope.activation_height || pool.IsNull() || !fetch) {
        return fail(HistoryStatus::MissingData, "tides-history-index-context");
    }
    const auto* genesis = previous->GetAncestor(0);
    if (!genesis || genesis->GetBlockHash() != impl.scope.genesis) return fail(HistoryStatus::MissingData, "tides-history-index-genesis");
    if (!required_work || uint32_t(previous->nHeight) < activation_height) {
        result.status = HistoryStatus::Ready;
        result.complete_to_activation = uint32_t(previous->nHeight) < activation_height;
        return result;
    }
    if (!NativeValidated(*previous)) return fail(HistoryStatus::MissingData, "tides-history-index-conditional-branch");
    try {
        std::unique_lock lock{impl.mutex};
        const auto fetch_delta = [&](const CBlockIndex& index) {
            // Never retain the index mutex while acquiring cs_main or invoking
            // native/archive code. All persistent records are immutable. A
            // concurrent builder's atomic result is rechecked after the fetch.
            lock.unlock();
            DeltaResult value;
            try {
                if (!NativeValidated(index)) value = DeltaResult::Missing({}, "tides-history-index-conditional-branch");
                else value = fetch(index);
            } catch (const std::bad_alloc&) { value = DeltaResult::Limited("tides-history-local-allocation"); }
            catch (const std::exception&) { value = DeltaResult::Missing({index.m_mm_rhs}, "tides-history-local-read"); }
            lock.lock();
            if (value.status != HistoryStatus::Ready) return value;
            if (!value.delta || !Matches(*value.delta, index)) return DeltaResult::Missing({index.m_mm_rhs}, "tides-history-anchor-mismatch");
            if (value.delta->admissions.size() > budget.entries - result.scanned_entries ||
                value.delta->encoded_bytes > budget.bytes - result.scanned_bytes) return DeltaResult::Limited("tides-history-delta-budget");
            if (!ValidAdmissions(value.delta->admissions)) return DeltaResult::Invalid("tides-history-admission");
            ++result.scanned_blocks;
            result.scanned_entries += value.delta->admissions.size();
            result.scanned_bytes += value.delta->encoded_bytes;
            return value;
        };
        auto covered = impl.Covered(*previous);
        if (!covered) {
            if (impl.disk_full) throw LocalLimit("tides-history-index-disk-budget");
            // A covered ancestor certifies its full prefix. Binary search
            // locates reusable progress after restart without replaying every
            // unrelated snapshot or retaining native index pointers on disk.
            uint32_t low = activation_height - 1;
            uint32_t high = previous->nHeight;
            std::optional<Coverage> base;
            while (low + 1 < high) {
                const auto middle = low + (high - low) / 2;
                const auto* ancestor = previous->GetAncestor(middle);
                if (!ancestor) throw LocalFailure("tides-history-index-ancestry");
                auto value = impl.Covered(*ancestor);
                if (value) { low = middle; base = value; }
                else high = middle;
            }
            auto root = base ? base->root : uint256{};
            for (uint32_t height = low + 1; height <= uint32_t(previous->nHeight); ++height) {
                if (result.scanned_blocks >= budget.blocks) return fail(HistoryStatus::ResourceLimit, "tides-history-index-rebuild-budget");
                const auto* ancestor = previous->GetAncestor(height);
                if (!ancestor) throw LocalFailure("tides-history-index-ancestry");
                if (const auto existing = impl.Covered(*ancestor)) {
                    if (existing->parent_root != root) throw LocalFailure("tides-history-index-parent-root");
                    root = existing->root;
                    covered = existing;
                    continue;
                }
                const auto fetched = fetch_delta(*ancestor);
                if (fetched.status != HistoryStatus::Ready) return fail(fetched.status, fetched.reason, fetched.missing);
                if (const auto concurrent = impl.Covered(*ancestor)) {
                    if (concurrent->parent_root != root) throw LocalFailure("tides-history-index-parent-root");
                    covered = concurrent;
                } else covered = impl.Add(*fetched.delta, root, budget.bytes);
                root = covered->root;
            }
        }
        if (!covered) throw LocalFailure("tides-history-index-coverage-missing");
        HashWriter writer;
        writer << impl.scope_id << previous->GetBlockHash() << pool << required_work.str();
        const auto query_id = writer.GetHash();
        const auto cache_budget = ConfiguredHistoryCacheBudget();
        auto position = impl.queries.find(query_id);
        if (position == impl.queries.end()) {
            while (impl.queries.size() >= cache_budget.queries) {
                if (!impl.Evict()) throw LocalLimit("tides-history-index-query-budget");
            }
            auto query = std::make_shared<Impl::Query>();
            query->next = impl.Find(covered->root, pool);
            query->before_height = uint32_t(previous->nHeight) + 1;
            query->remaining = required_work;
            position = impl.queries.emplace(query_id, std::move(query)).first;
        }
        const auto query = position->second;
        query->touched = ++impl.clock;
        while (!query->complete) {
            if (query->next.IsNull()) { query->complete = query->to_activation = true; break; }
            if (result.scanned_blocks >= budget.blocks) return fail(HistoryStatus::ResourceLimit, "tides-history-index-query-block-budget");
            const auto expected_next = query->next;
            PoolBatch batch;
            if (!impl.db.Read(std::pair{uint8_t{'B'}, expected_next}, batch) || batch.Id() != expected_next ||
                batch.pool != pool || !batch.count || batch.height < activation_height || batch.height >= query->before_height) {
                throw LocalFailure("tides-history-index-batch-unavailable");
            }
            const auto* ancestor = previous->GetAncestor(batch.height);
            if (!ancestor || !ancestor->pprev || ancestor->GetBlockHash() != batch.block ||
                ancestor->pprev->GetBlockHash() != batch.parent || ancestor->m_mm_rhs != batch.snapshot) {
                throw LocalFailure("tides-history-index-batch-ancestry");
            }
            const auto fetched = fetch_delta(*ancestor);
            if (fetched.status != HistoryStatus::Ready) return fail(fetched.status, fetched.reason, fetched.missing);
            // The same request may have progressed while this call fetched.
            if (query->next != expected_next) continue;
            std::vector<Admission> selected;
            size_t bytes{0};
            for (const auto& entry : fetched.delta->admissions) if (entry.pool == pool) {
                const auto charge = sizeof(Admission) + entry.payout_script.size();
                if (charge > cache_budget.query_bytes - std::min(bytes, cache_budget.query_bytes)) throw LocalLimit("tides-history-index-query-budget");
                bytes += charge;
                selected.push_back(entry);
                selected.back().admission_height = batch.height;
            }
            if (selected.size() != batch.count || AdmissionsHash(selected) != batch.admissions) {
                throw LocalFailure("tides-history-index-batch-admissions");
            }
            if (bytes > cache_budget.query_bytes - std::min(query->bytes, cache_budget.query_bytes)) throw LocalLimit("tides-history-index-query-budget");
            while (bytes > cache_budget.query_bytes - std::min(impl.query_bytes, cache_budget.query_bytes)) {
                if (!impl.Evict(query)) throw LocalLimit("tides-history-index-query-budget");
            }
            query->reverse.reserve(query->reverse.size() + selected.size());
            for (auto it = selected.rbegin(); it != selected.rend(); ++it) {
                query->remaining -= std::min(query->remaining, Numeric(it->work));
                query->reverse.push_back(std::move(*it));
            }
            query->bytes += bytes;
            impl.query_bytes += bytes;
            query->next = batch.prior;
            query->before_height = batch.height;
            query->complete = query->remaining == 0;
        }
        result.entries.reserve(query->reverse.size());
        for (auto it = query->reverse.rbegin(); it != query->reverse.rend(); ++it) {
            result.entries.push_back({result.entries.size() + 1, it->proof_id, it->pool, it->payout_script, it->work, it->admission_height});
        }
        result.status = HistoryStatus::Ready;
        result.complete_to_activation = query->to_activation;
        return result;
    } catch (const LocalLimit& e) { return fail(HistoryStatus::ResourceLimit, e.what()); }
    catch (const std::bad_alloc&) { return fail(HistoryStatus::ResourceLimit, "tides-history-local-allocation"); }
    catch (const std::length_error&) { return fail(HistoryStatus::ResourceLimit, "tides-history-local-allocation"); }
    catch (const std::exception&) { return fail(HistoryStatus::MissingData, "tides-history-index-unavailable"); }
}
} // namespace sharepool::tides
