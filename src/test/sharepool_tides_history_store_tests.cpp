// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/tides_history_store.h>

#include <arith_uint256.h>
#include <chain.h>
#include <dbwrapper.h>
#include <kernel/cs_main.h>
#include <test/util/setup_common.h>
#include <util/readwritefile.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <barrier>
#include <future>
#include <set>

namespace {
namespace tides = sharepool::tides;
struct RawValue {
    const DataStream& bytes;
    template <typename Stream> void Serialize(Stream& out) const { out.write({bytes.data(), bytes.size()}); }
};
uint256 Number(uint64_t value) { return ArithToUint256(arith_uint256{value}); }
std::vector<unsigned char> Script(unsigned char owner)
{
    std::vector<unsigned char> script{0, 20};
    script.resize(22, owner);
    return script;
}
tides::Admission Admit(uint64_t proof, uint64_t pool = 1, uint64_t work = 8)
{
    return {Number(proof), Number(pool), Script(proof % 250 + 1), Number(work)};
}

struct StoreFixture : BasicTestingSetup {
    struct Node { uint256 hash; CBlockIndex index; };
    std::vector<std::unique_ptr<Node>> nodes;
    std::map<uint256, std::shared_ptr<tides::HistoryDelta>> deltas;
    std::map<uint256, size_t> reads;
    std::set<uint256> missing;
    fs::path path{m_path_root / "tides-history-store"};
    StoreFixture() { Add(nullptr, {}); }
    Node* Add(Node* parent, std::vector<tides::Admission> admissions)
    {
        auto node = std::make_unique<Node>();
        node->hash = Number(1000 + nodes.size());
        node->index.phashBlock = &node->hash;
        node->index.pprev = parent ? &parent->index : nullptr;
        node->index.nHeight = parent ? parent->index.nHeight + 1 : 0;
        node->index.m_mm_rhs = Number(5000 + nodes.size());
        { LOCK(cs_main); node->index.nStatus = BLOCK_VALID_SCRIPTS; }
        node->index.BuildSkip();
        if (parent) deltas.emplace(node->hash, std::make_shared<tides::HistoryDelta>(tides::HistoryDelta{
            node->hash, parent->hash, node->index.m_mm_rhs, uint32_t(node->index.nHeight),
            512 + admissions.size() * 200, std::move(admissions)}));
        auto* result = node.get();
        nodes.push_back(std::move(node));
        return result;
    }
    tides::PersistentHistoryIndex::Scope Scope(uint32_t profile = 6) const
    {
        return {nodes.front()->hash, Number(7000 + profile), profile, 1};
    }
    tides::DeltaResult Fetch(const CBlockIndex& index)
    {
        ++reads[index.GetBlockHash()];
        if (missing.contains(index.GetBlockHash())) return tides::DeltaResult::Missing({index.m_mm_rhs});
        return tides::DeltaResult::Ready(deltas.at(index.GetBlockHash()));
    }
    tides::HistoryWindow Read(tides::PersistentHistoryIndex& store, Node* tip, uint64_t work = 8,
                             uint64_t pool = 1, tides::HistoryBudget budget = {})
    {
        return store.ReadPool(&tip->index, 1, Number(pool), tides::Work{work},
            [&](const CBlockIndex& index) { return Fetch(index); }, budget);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(sharepool_tides_history_store_tests, StoreFixture)

BOOST_AUTO_TEST_CASE(sparse_pool_restart_reads_only_selected_native_admissions)
{
    auto* first = Add(nodes.front().get(), {Admit(1)});
    auto* tip = first;
    for (uint64_t proof{2}; proof <= 100; ++proof) tip = Add(tip, {Admit(proof, 2)});
    uint64_t charged{0};
    {
        tides::PersistentHistoryIndex store{path, Scope(), {}};
        const auto cold = Read(store, tip);
        BOOST_REQUIRE(cold.status == tides::HistoryStatus::Ready);
        BOOST_REQUIRE_EQUAL(cold.entries.size(), 1);
        BOOST_CHECK(cold.entries.front().proof_id == Number(1));
        BOOST_CHECK_EQUAL(store.GetStats().covered_blocks, 100);
        BOOST_CHECK_EQUAL(store.GetStats().pool_batches, 100);
        BOOST_CHECK(store.GetStats().map_nodes < 300);
        charged = store.GetStats().charged_bytes;
    }
    reads.clear();
    tides::PersistentHistoryIndex reopened{path, Scope(), {}};
    const auto warm = Read(reopened, tip);
    BOOST_REQUIRE(warm.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(warm.entries.size(), 1);
    BOOST_CHECK_EQUAL(warm.scanned_blocks, 1);
    BOOST_REQUIRE_EQUAL(reads.size(), 1);
    BOOST_CHECK_EQUAL(reads.at(first->hash), 1);
    BOOST_CHECK_EQUAL(reopened.GetStats().charged_bytes, charged);
    const auto absent = Read(reopened, tip, 8, 99);
    BOOST_REQUIRE(absent.status == tides::HistoryStatus::Ready);
    BOOST_CHECK(absent.complete_to_activation);
    BOOST_CHECK(absent.entries.empty());
    BOOST_CHECK_EQUAL(absent.scanned_blocks, 0);
}

BOOST_AUTO_TEST_CASE(rebuild_progress_is_atomic_and_resumes_after_restart)
{
    auto* tip = Add(nodes.front().get(), {Admit(1)});
    for (size_t i{0}; i < 6; ++i) tip = Add(tip, {});
    for (size_t round{0}; round < 3; ++round) {
        tides::PersistentHistoryIndex store{path, Scope(), {}};
        const auto limited = Read(store, tip, 8, 1, {2, 100, 8192});
        BOOST_REQUIRE(limited.status == tides::HistoryStatus::ResourceLimit);
        BOOST_CHECK(limited.entries.empty());
        BOOST_CHECK(!limited.complete_to_activation);
        BOOST_CHECK_EQUAL(store.GetStats().covered_blocks, 2 * (round + 1));
    }
    tides::PersistentHistoryIndex store{path, Scope(), {}};
    const auto ready = Read(store, tip, 8, 1, {2, 100, 8192});
    BOOST_REQUIRE(ready.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(ready.entries.size(), 1);
    BOOST_CHECK_EQUAL(store.GetStats().covered_blocks, 7);
    for (const auto& [hash, count] : reads) BOOST_CHECK_EQUAL(count, hash == nodes[1]->hash ? 2 : 1);
}

BOOST_AUTO_TEST_CASE(branch_roots_preserve_pool_identity_and_complete_height_boundary)
{
    auto* common = Add(nodes.front().get(), {Admit(1), Admit(2, 2)});
    auto* left = Add(common, {Admit(3), Admit(4), Admit(5, 2)});
    auto* right = Add(common, {Admit(6, 2)});
    auto* right_tip = Add(right, {Admit(7)});
    tides::PersistentHistoryIndex store{path, Scope(), {}};
    const auto a = Read(store, left, 1);
    BOOST_REQUIRE(a.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(a.entries.size(), 2);
    BOOST_CHECK(a.entries[0].proof_id == Number(3));
    BOOST_CHECK(a.entries[1].proof_id == Number(4));
    for (const auto& entry : a.entries) BOOST_CHECK_EQUAL(entry.admission_height, 2);
    const auto b = Read(store, right, 1);
    BOOST_REQUIRE_EQUAL(b.entries.size(), 1);
    BOOST_CHECK(b.entries[0].proof_id == Number(1));
    const auto c = Read(store, right_tip, 16);
    BOOST_REQUIRE_EQUAL(c.entries.size(), 2);
    BOOST_CHECK(c.entries[0].proof_id == Number(1));
    BOOST_CHECK(c.entries[1].proof_id == Number(7));
    const auto other = Read(store, right, 1, 2);
    BOOST_REQUIRE_EQUAL(other.entries.size(), 1);
    BOOST_CHECK(other.entries[0].proof_id == Number(6));
    BOOST_CHECK_EQUAL(store.GetStats().covered_blocks, 4);
    BOOST_CHECK_EQUAL(Read(store, left, 1).entries.size(), 2);
}

BOOST_AUTO_TEST_CASE(all_pool_keys_and_updates_use_bounded_persistent_paths)
{
    std::vector<tides::Admission> entries;
    for (uint64_t i{1}; i <= 256; ++i) entries.push_back(Admit(i, i));
    auto* first = Add(nodes.front().get(), entries);
    auto* next = Add(first, {Admit(257, 129)});
    tides::PersistentHistoryIndex store{path, Scope(), {}};
    BOOST_REQUIRE(Read(store, first).status == tides::HistoryStatus::Ready);
    const auto initial_nodes = store.GetStats().map_nodes;
    for (uint64_t pool{1}; pool <= 256; ++pool) {
        const auto result = Read(store, next, 1, pool);
        BOOST_REQUIRE(result.status == tides::HistoryStatus::Ready);
        BOOST_REQUIRE_EQUAL(result.entries.size(), 1);
        BOOST_CHECK(result.entries.front().proof_id == Number(pool == 129 ? 257 : pool));
    }
    BOOST_CHECK(store.GetStats().map_nodes - initial_nodes < 20);
    BOOST_CHECK(Read(store, next, 1, 257).complete_to_activation);
}

BOOST_AUTO_TEST_CASE(missing_and_changed_source_snapshots_never_use_stored_amounts)
{
    auto* first = Add(nodes.front().get(), {Admit(1)});
    auto* tip = Add(first, {Admit(2, 2)});
    { tides::PersistentHistoryIndex store{path, Scope(), {}}; BOOST_REQUIRE(Read(store, tip).status == tides::HistoryStatus::Ready); }
    missing.insert(first->hash);
    tides::PersistentHistoryIndex reopened{path, Scope(), {}};
    const auto unavailable = Read(reopened, tip);
    BOOST_CHECK(unavailable.status == tides::HistoryStatus::MissingData);
    BOOST_CHECK(unavailable.entries.empty());
    BOOST_CHECK(!unavailable.complete_to_activation);
    missing.clear();
    deltas.at(first->hash)->admissions.front().work = Number(9);
    const auto changed = Read(reopened, tip);
    BOOST_CHECK(changed.status == tides::HistoryStatus::MissingData);
    BOOST_CHECK(changed.entries.empty());
    deltas.at(first->hash)->admissions.front().work = Number(8);
    BOOST_REQUIRE(Read(reopened, tip).status == tides::HistoryStatus::Ready);
}

BOOST_AUTO_TEST_CASE(missing_source_during_rebuild_cannot_mark_prefix_complete)
{
    auto* first = Add(nodes.front().get(), {Admit(1)});
    auto* tip = Add(first, {});
    missing.insert(first->hash);
    tides::PersistentHistoryIndex store{path, Scope(), {}};
    const auto result = Read(store, tip, 8, 99);
    BOOST_CHECK(result.status == tides::HistoryStatus::MissingData);
    BOOST_CHECK(result.entries.empty());
    BOOST_CHECK(!result.complete_to_activation);
    BOOST_CHECK_EQUAL(store.GetStats().covered_blocks, 0);
    missing.clear();
    BOOST_CHECK(Read(store, tip, 8, 99).complete_to_activation);
}

BOOST_AUTO_TEST_CASE(conditional_branch_is_not_promoted_to_durable_coverage)
{
    auto* tip = Add(nodes.front().get(), {Admit(1)});
    { LOCK(cs_main); tip->index.nStatus = BLOCK_VALID_TRANSACTIONS; }
    tides::PersistentHistoryIndex store{path, Scope(), {}};
    const auto result = Read(store, tip);
    BOOST_CHECK(result.status == tides::HistoryStatus::MissingData);
    BOOST_CHECK(result.entries.empty());
    BOOST_CHECK_EQUAL(store.GetStats().covered_blocks, 0);
    BOOST_CHECK(reads.empty());
    { LOCK(cs_main); tip->index.nStatus = BLOCK_VALID_SCRIPTS; }
    BOOST_CHECK(Read(store, tip).status == tides::HistoryStatus::Ready);
}

BOOST_AUTO_TEST_CASE(profile_genesis_rules_and_activation_are_explicit)
{
    auto* tip = Add(nodes.front().get(), {Admit(1)});
    {
        tides::PersistentHistoryIndex store{path, Scope(7), {}};
        const auto scope = Scope(7);
        BOOST_CHECK(store.MatchesScope(scope.genesis, scope.rules, 7, 1));
        BOOST_CHECK(!store.MatchesScope(scope.genesis, scope.rules, 6, 1));
        BOOST_CHECK(!store.MatchesScope(Number(2), scope.rules, 7, 1));
        BOOST_CHECK(!store.MatchesScope(scope.genesis, Number(2), 7, 1));
        BOOST_CHECK(!store.MatchesScope(scope.genesis, scope.rules, 7, 2));
        BOOST_CHECK(Read(store, tip).status == tides::HistoryStatus::Ready);
    }
    BOOST_CHECK_THROW((tides::PersistentHistoryIndex{path, Scope(6), {}}), std::runtime_error);
    auto wrong = Scope(7);
    wrong.genesis = Number(9);
    tides::PersistentHistoryIndex other{path / "other", wrong, {}};
    BOOST_CHECK(Read(other, tip).status == tides::HistoryStatus::MissingData);
}

BOOST_AUTO_TEST_CASE(disk_and_query_limits_preserve_complete_batches_and_resume)
{
    auto* first = Add(nodes.front().get(), {Admit(1), Admit(2), Admit(3)});
    {
        tides::PersistentHistoryIndex limited{path, Scope(), {.max_bytes = 500}};
        const auto result = Read(limited, first, 1);
        BOOST_CHECK(result.status == tides::HistoryStatus::ResourceLimit);
        BOOST_CHECK(result.entries.empty());
        BOOST_CHECK_EQUAL(limited.GetStats().covered_blocks, 0);
    }
    tides::PersistentHistoryIndex store{path, Scope(), {}};
    BOOST_REQUIRE(Read(store, first, 1).status == tides::HistoryStatus::Ready);
    auto* tip = first;
    for (uint64_t proof{4}; proof <= 8; ++proof) tip = Add(tip, {Admit(proof)});
    BOOST_REQUIRE(Read(store, tip, 1).status == tides::HistoryStatus::Ready);
    for (size_t attempt{0}; attempt < 5; ++attempt) {
        const auto limited = Read(store, tip, 64, 1, {1, 100, 8192});
        BOOST_REQUIRE(limited.status == tides::HistoryStatus::ResourceLimit);
        BOOST_CHECK(limited.entries.empty());
        BOOST_CHECK_EQUAL(limited.scanned_blocks, 1);
    }
    const auto ready = Read(store, tip, 64, 1, {1, 100, 8192});
    BOOST_REQUIRE(ready.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(ready.entries.size(), 8);
    for (size_t i{0}; i < ready.entries.size(); ++i) BOOST_CHECK(ready.entries[i].proof_id == Number(i + 1));
}

BOOST_AUTO_TEST_CASE(missing_key_or_key_replacement_requires_rebuild)
{
    auto* tip = Add(nodes.front().get(), {Admit(1)});
    { tides::PersistentHistoryIndex store{path, Scope(), {}}; BOOST_REQUIRE(Read(store, tip).status == tides::HistoryStatus::Ready); }
    BOOST_REQUIRE(fs::remove(path / "seal.key"));
    BOOST_CHECK_THROW((tides::PersistentHistoryIndex{path, Scope(), {}}), std::runtime_error);
    {
        tides::PersistentHistoryIndex rebuilt{path, Scope(), {.rebuild = true}};
        BOOST_CHECK_EQUAL(rebuilt.GetStats().covered_blocks, 0);
        BOOST_REQUIRE(Read(rebuilt, tip).status == tides::HistoryStatus::Ready);
    }
    BOOST_REQUIRE(WriteBinaryFile(path / "seal.key", std::string(32, 'x')));
    BOOST_CHECK_THROW((tides::PersistentHistoryIndex{path, Scope(), {}}), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(damaged_or_forged_empty_coverage_never_bootstraps_an_empty_pool)
{
    auto* tip = Add(nodes.front().get(), {Admit(1)});
    { tides::PersistentHistoryIndex store{path, Scope(), {}}; BOOST_REQUIRE(Read(store, tip).status == tides::HistoryStatus::Ready); }
    {
        CDBWrapper db{DBParams{.path = path / "index", .cache_bytes = 1 << 20}};
        // Exact fixed coverage record fields, with a forged empty map root and
        // no valid process-owned seal. The native block anchor is unchanged.
        DataStream raw;
        raw << tip->hash << tip->index.pprev->GetBlockHash() << tip->index.m_mm_rhs
            << uint32_t(tip->index.nHeight) << uint256{} << uint256{} << uint256{};
        BOOST_REQUIRE(db.Write(std::pair{uint8_t{'C'}, tip->hash}, RawValue{raw}, true));
    }
    tides::PersistentHistoryIndex reopened{path, Scope(), {}};
    const auto result = Read(reopened, tip);
    BOOST_CHECK(result.status == tides::HistoryStatus::MissingData);
    BOOST_CHECK(result.entries.empty());
    BOOST_CHECK(!result.complete_to_activation);
}

BOOST_AUTO_TEST_CASE(fetch_callback_can_reenter_index_without_lock_inversion)
{
    auto* tip = Add(nodes.front().get(), {Admit(1)});
    tides::PersistentHistoryIndex store{path, Scope(), {}};
    size_t callbacks{0};
    const auto result = store.ReadPool(&tip->index, 1, Number(1), 8, [&](const CBlockIndex& index) {
        LOCK(cs_main);
        ++callbacks;
        (void)store.GetStats(); // Requires the local mutex; it must be released during fetch.
        return Fetch(index);
    });
    BOOST_REQUIRE(result.status == tides::HistoryStatus::Ready);
    BOOST_CHECK_EQUAL(callbacks, 2);
}

BOOST_AUTO_TEST_CASE(concurrent_rebuild_and_query_commit_a_batch_only_once)
{
    auto* tip = Add(nodes.front().get(), {Admit(1), Admit(2)});
    tides::PersistentHistoryIndex store{path, Scope(), {}};
    std::barrier rendezvous{2};
    std::atomic<size_t> callbacks{0};
    const auto delta = deltas.at(tip->hash);
    const auto call = [&] {
        return store.ReadPool(&tip->index, 1, Number(1), 1, [&](const CBlockIndex&) {
            if (callbacks.fetch_add(1) < 2) rendezvous.arrive_and_wait();
            return tides::DeltaResult::Ready(delta);
        });
    };
    auto a = std::async(std::launch::async, call);
    auto b = std::async(std::launch::async, call);
    const auto first = a.get();
    const auto second = b.get();
    BOOST_REQUIRE(first.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE(second.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(first.entries.size(), 2);
    BOOST_REQUIRE_EQUAL(second.entries.size(), 2);
    BOOST_CHECK(first.entries[0].proof_id == second.entries[0].proof_id);
    BOOST_CHECK(first.entries[1].proof_id == second.entries[1].proof_id);
    BOOST_CHECK_EQUAL(store.GetStats().covered_blocks, 1);
    BOOST_CHECK_EQUAL(store.GetStats().pool_batches, 1);
}

BOOST_AUTO_TEST_CASE(missing_map_nodes_remain_unavailable_and_authoritative_scan_can_recover)
{
    auto* tip = Add(nodes.front().get(), {Admit(1)});
    { tides::PersistentHistoryIndex store{path, Scope(), {}}; BOOST_REQUIRE(Read(store, tip).status == tides::HistoryStatus::Ready); }
    {
        CDBWrapper db{DBParams{.path = path / "index", .cache_bytes = 1 << 20}};
        std::unique_ptr<CDBIterator> it{db.NewIterator()};
        it->Seek(std::pair{uint8_t{'N'}, uint256{}});
        std::vector<std::pair<uint8_t, uint256>> erase;
        while (it->Valid()) {
            std::pair<uint8_t, uint256> key;
            BOOST_REQUIRE(it->GetKey(key));
            if (key.first != uint8_t{'N'}) break;
            erase.push_back(key);
            it->Next();
        }
        BOOST_REQUIRE(!erase.empty());
        CDBBatch batch{db};
        for (const auto& key : erase) batch.Erase(key);
        BOOST_REQUIRE(db.WriteBatch(batch, true));
    }
    tides::PersistentHistoryIndex reopened{path, Scope(), {}};
    for (uint64_t pool : {1, 99}) {
        const auto result = Read(reopened, tip, 8, pool);
        BOOST_CHECK(result.status == tides::HistoryStatus::MissingData);
        BOOST_CHECK(result.entries.empty());
        BOOST_CHECK(!result.complete_to_activation);
    }
    tides::HistoryIndex authoritative;
    const auto recovered = authoritative.ReadPool(&tip->index, 1, Number(1), 8,
        [&](const auto& index) { return Fetch(index); });
    BOOST_REQUIRE(recovered.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(recovered.entries.size(), 1);
    BOOST_CHECK(recovered.entries.front().proof_id == Number(1));
}

BOOST_AUTO_TEST_CASE(invalid_local_options_do_not_destroy_an_existing_index)
{
    auto* tip = Add(nodes.front().get(), {Admit(1)});
    uint64_t blocks{0};
    {
        tides::PersistentHistoryIndex store{path, Scope(), {}};
        BOOST_REQUIRE(Read(store, tip).status == tides::HistoryStatus::Ready);
        blocks = store.GetStats().covered_blocks;
    }
    BOOST_CHECK_THROW((tides::PersistentHistoryIndex{path, Scope(), {.max_bytes = 0, .rebuild = true}}), std::invalid_argument);
    BOOST_CHECK_THROW((tides::PersistentHistoryIndex{path, Scope(), {.cache_bytes = 0, .rebuild = true}}), std::invalid_argument);
    auto wrong = Scope();
    wrong.activation_height = 0;
    BOOST_CHECK_THROW((tides::PersistentHistoryIndex{path, wrong, {.rebuild = true}}), std::invalid_argument);
    tides::PersistentHistoryIndex reopened{path, Scope(), {}};
    BOOST_CHECK_EQUAL(reopened.GetStats().covered_blocks, blocks);
    BOOST_CHECK(Read(reopened, tip).status == tides::HistoryStatus::Ready);
}

BOOST_AUTO_TEST_SUITE_END()
