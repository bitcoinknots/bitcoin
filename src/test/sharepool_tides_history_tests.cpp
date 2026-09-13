// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/tides_history.h>

#include <arith_uint256.h>
#include <chain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <limits>
#include <set>

namespace {
namespace tides = sharepool::tides;

uint256 Number(uint64_t value) { return ArithToUint256(arith_uint256{value}); }
std::vector<unsigned char> Script(unsigned char id)
{
    std::vector<unsigned char> script{0, 20};
    script.resize(22, id);
    return script;
}
tides::Admission Admit(uint64_t proof, unsigned char owner, uint64_t work = 8, uint64_t pool = 1)
{
    return {Number(proof), Number(pool), Script(owner), Number(work)};
}

struct HistoryFixture : BasicTestingSetup {
    struct Node {
        uint256 hash;
        CBlockIndex index;
    };
    std::vector<std::unique_ptr<Node>> nodes;
    std::map<uint256, std::shared_ptr<tides::HistoryDelta>> deltas;
    std::set<uint256> missing;
    std::map<uint256, size_t> reads;

    HistoryFixture() { Add(nullptr, {}); }

    Node* Add(Node* parent, std::vector<tides::Admission> entries)
    {
        auto node = std::make_unique<Node>();
        node->hash = Number(1000 + nodes.size());
        node->index.phashBlock = &node->hash;
        node->index.pprev = parent ? &parent->index : nullptr;
        node->index.nHeight = parent ? parent->index.nHeight + 1 : 0;
        node->index.m_mm_rhs = Number(5000 + nodes.size());
        node->index.BuildSkip();
        if (parent) {
            deltas.emplace(node->hash, std::make_shared<tides::HistoryDelta>(tides::HistoryDelta{
                node->hash, parent->hash, node->index.m_mm_rhs, uint32_t(node->index.nHeight),
                512 + entries.size() * 200, std::move(entries)}));
        }
        auto* result = node.get();
        nodes.push_back(std::move(node));
        return result;
    }

    tides::DeltaResult Fetch(const CBlockIndex& index)
    {
        ++reads[index.GetBlockHash()];
        if (missing.contains(index.GetBlockHash())) return tides::DeltaResult::Missing({index.m_mm_rhs});
        return tides::DeltaResult::Ready(deltas.at(index.GetBlockHash()));
    }

    tides::HistoryWindow Read(tides::HistoryIndex& history, Node* tip, uint64_t work = 8,
                              uint64_t pool = 1, tides::HistoryBudget budget = {})
    {
        return history.ReadPool(&tip->index, 1, Number(pool), tides::Work{work},
            [this](const CBlockIndex& index) { return Fetch(index); }, budget);
    }

    void RebuildIndices()
    {
        std::vector<std::unique_ptr<Node>> rebuilt;
        std::map<uint256, Node*> by_hash;
        for (const auto& old : nodes) {
            auto fresh = std::make_unique<Node>();
            fresh->hash = old->hash;
            fresh->index.phashBlock = &fresh->hash;
            fresh->index.nHeight = old->index.nHeight;
            fresh->index.m_mm_rhs = old->index.m_mm_rhs;
            fresh->index.pprev = old->index.pprev ? &by_hash.at(old->index.pprev->GetBlockHash())->index : nullptr;
            fresh->index.BuildSkip();
            by_hash.emplace(fresh->hash, fresh.get());
            rebuilt.push_back(std::move(fresh));
        }
        nodes.swap(rebuilt); // Destroy every original CBlockIndex object.
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(sharepool_tides_history_tests, HistoryFixture)

BOOST_AUTO_TEST_CASE(chronological_exact_work_suffix_retains_full_boundary_share)
{
    auto* first = Add(nodes.front().get(), {Admit(1, 1, 10)});
    auto* second = Add(first, {Admit(2, 2, 5)});
    auto* third = Add(second, {Admit(3, 3, 8)});
    tides::HistoryIndex history;
    const auto result = Read(history, third, 10);
    BOOST_REQUIRE(result.status == tides::HistoryStatus::Ready);
    BOOST_CHECK(!result.complete_to_activation);
    BOOST_REQUIRE_EQUAL(result.entries.size(), 2);
    BOOST_CHECK_EQUAL(result.entries[0].sequence, 1);
    BOOST_CHECK_EQUAL(result.entries[1].sequence, 2);
    BOOST_CHECK(result.entries[0].proof_id == Number(2));
    BOOST_CHECK(result.entries[1].proof_id == Number(3));
    BOOST_CHECK(result.entries[0].work == Number(5));
    BOOST_CHECK_EQUAL(reads[first->hash], 0);
    // The caller's work target determines the later clipping. A returned suffix
    // contains the full original boundary admission, never a rewritten share.
    const auto reward = tides::CalculateRewards(result.entries, {Number(1), 2, Number(3)}, Number(1), 80, 0, {2, 2});
    BOOST_REQUIRE_EQUAL(reward.payouts.size(), 1);
    BOOST_CHECK_EQUAL(reward.payouts[0].nValue, 80);
}

BOOST_AUTO_TEST_CASE(startup_and_absent_pool_require_complete_scan_to_activation)
{
    auto* first = Add(nodes.front().get(), {Admit(1, 1, 3)});
    auto* tip = Add(first, {});
    tides::HistoryIndex history;
    const auto startup = Read(history, tip, 80);
    BOOST_REQUIRE(startup.status == tides::HistoryStatus::Ready);
    BOOST_CHECK(startup.complete_to_activation);
    BOOST_REQUIRE_EQUAL(startup.entries.size(), 1);
    const auto absent = Read(history, tip, 8, 99);
    BOOST_REQUIRE(absent.status == tides::HistoryStatus::Ready);
    BOOST_CHECK(absent.complete_to_activation);
    BOOST_CHECK(absent.entries.empty());
    const auto zero = Read(history, tip, 0);
    BOOST_REQUIRE(zero.status == tides::HistoryStatus::Ready);
    BOOST_CHECK(zero.entries.empty());
    BOOST_CHECK(!zero.complete_to_activation);
}

BOOST_AUTO_TEST_CASE(competing_branches_and_repeated_rewards_do_not_mutate_history)
{
    auto* common = Add(nodes.front().get(), {Admit(1, 1)});
    auto* left = Add(common, {Admit(2, 2)});
    auto* right = Add(common, {Admit(3, 3)});
    tides::HistoryIndex history;
    const auto a = Read(history, left);
    const auto b = Read(history, right);
    BOOST_REQUIRE(a.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE(b.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(a.entries.size(), 1);
    BOOST_REQUIRE_EQUAL(b.entries.size(), 1);
    BOOST_CHECK(a.entries[0].payout_script == Script(2));
    BOOST_CHECK(b.entries[0].payout_script == Script(3));
    BOOST_CHECK(Read(history, left).entries[0].proof_id == Number(2));
    history.Clear();
    BOOST_CHECK(Read(history, left).entries[0].proof_id == Number(2));
    BOOST_CHECK_EQUAL(reads[left->hash], 2);
}

BOOST_AUTO_TEST_CASE(higher_difficulty_retrieves_history_below_previous_window)
{
    auto* first = Add(nodes.front().get(), {Admit(1, 1)});
    auto* tip = Add(first, {Admit(2, 2)});
    tides::HistoryIndex history;
    BOOST_REQUIRE_EQUAL(Read(history, tip).entries.size(), 1);
    BOOST_CHECK_EQUAL(reads[first->hash], 0);
    const auto larger = Read(history, tip, 16);
    BOOST_REQUIRE(larger.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(larger.entries.size(), 2);
    BOOST_CHECK(larger.entries[0].proof_id == Number(1));
    BOOST_CHECK(larger.entries[1].proof_id == Number(2));
    const auto reward = tides::CalculateRewards(larger.entries, {Number(1), 2, Number(2)}, Number(2), 120, 0, {2, 2});
    BOOST_REQUIRE_EQUAL(reward.payouts.size(), 2);
    BOOST_CHECK_EQUAL(reward.payouts[0].nValue, 60);
    BOOST_CHECK_EQUAL(reward.payouts[1].nValue, 60);
}

BOOST_AUTO_TEST_CASE(missing_data_keeps_progress_but_never_returns_partial_entitlements)
{
    auto* first = Add(nodes.front().get(), {Admit(1, 1)});
    auto* tip = Add(first, {Admit(2, 2)});
    missing.insert(first->hash);
    tides::HistoryIndex history;
    const auto blocked = Read(history, tip, 16);
    BOOST_CHECK(blocked.status == tides::HistoryStatus::MissingData);
    BOOST_CHECK(blocked.entries.empty());
    BOOST_CHECK(!blocked.complete_to_activation);
    BOOST_CHECK(blocked.missing == std::vector<uint256>{first->index.m_mm_rhs});
    BOOST_CHECK(Read(history, tip, 16).status == tides::HistoryStatus::MissingData);
    BOOST_CHECK_EQUAL(reads[tip->hash], 1);
    missing.erase(first->hash);
    const auto ready = Read(history, tip, 16);
    BOOST_REQUIRE(ready.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(ready.entries.size(), 2);
    BOOST_CHECK_EQUAL(reads[tip->hash], 1);
}

BOOST_AUTO_TEST_CASE(empty_block_scans_resume_across_local_budget_and_cache_eviction)
{
    auto* tip = Add(nodes.front().get(), {Admit(1, 1)});
    for (size_t i{0}; i < 6; ++i) tip = Add(tip, {});
    tides::HistoryIndex history{{1, 1024, 2, 4096}};
    for (size_t i{0}; i < 3; ++i) {
        const auto limited = Read(history, tip, 8, 1, {2, 100, 8192});
        BOOST_CHECK(limited.status == tides::HistoryStatus::ResourceLimit);
        BOOST_CHECK(limited.entries.empty());
        BOOST_CHECK(!limited.complete_to_activation);
        BOOST_CHECK_EQUAL(limited.scanned_blocks, 2);
    }
    const auto ready = Read(history, tip, 8, 1, {2, 100, 8192});
    BOOST_REQUIRE(ready.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(ready.entries.size(), 1);
    for (const auto& [hash, count] : reads) BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(delta_and_query_budgets_are_local_failures_not_empty_or_invalid_history)
{
    auto* tip = Add(nodes.front().get(), {Admit(1, 1), Admit(2, 2), Admit(3, 3)});
    tides::HistoryIndex history;
    const auto small_count = Read(history, tip, 24, 1, {1, 1, 8192});
    BOOST_CHECK(small_count.status == tides::HistoryStatus::ResourceLimit);
    BOOST_CHECK(small_count.entries.empty());
    const auto small_bytes = Read(history, tip, 24, 1, {1, 3, 1});
    BOOST_CHECK(small_bytes.status == tides::HistoryStatus::ResourceLimit);
    BOOST_CHECK(small_bytes.entries.empty());
    BOOST_REQUIRE_EQUAL(Read(history, tip, 24).entries.size(), 3);
    tides::HistoryIndex tiny_queries{{1, 8192, 1, 64}};
    const auto tiny = Read(tiny_queries, tip, 24);
    BOOST_CHECK(tiny.status == tides::HistoryStatus::ResourceLimit);
    BOOST_CHECK(tiny.entries.empty());
}

BOOST_AUTO_TEST_CASE(raising_query_budget_resumes_without_losing_acknowledged_work_or_progress)
{
    auto* first = Add(nodes.front().get(), {Admit(1, 1)});
    auto* tip = Add(first, {Admit(2, 2)});
    const size_t entry_bytes = sizeof(tides::Admission) + Script(1).size();
    // Disable the optional delta cache, so rereading the tip would reveal a
    // discarded cursor instead of being hidden by a cache hit.
    tides::HistoryIndex history{{0, 0, 1, entry_bytes}};
    const auto limited = Read(history, tip, 16);
    BOOST_REQUIRE(limited.status == tides::HistoryStatus::ResourceLimit);
    BOOST_CHECK_EQUAL(limited.reason, "tides-history-query-budget");
    BOOST_CHECK_EQUAL(limited.scanned_blocks, 1);
    BOOST_CHECK(limited.entries.empty());
    BOOST_CHECK_EQUAL(reads[tip->hash], 1);
    BOOST_CHECK_THROW(history.SetCacheBudget({0, 0, 0, entry_bytes * 2}), std::invalid_argument);
    history.SetCacheBudget({0, 0, 1, entry_bytes * 2});
    const auto ready = Read(history, tip, 16);
    BOOST_REQUIRE(ready.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(ready.entries.size(), 2);
    BOOST_CHECK(ready.entries[0].proof_id == Number(1));
    BOOST_CHECK(ready.entries[1].proof_id == Number(2));
    BOOST_CHECK_EQUAL(reads[tip->hash], 1);
    BOOST_CHECK_EQUAL(ready.scanned_blocks, 1);

    // Lowering a local budget may evict the derived query, but must never
    // silently return the affordable prefix as the complete entitlement set.
    history.SetCacheBudget({0, 0, 1, entry_bytes});
    const auto reduced = Read(history, tip, 16);
    BOOST_CHECK(reduced.status == tides::HistoryStatus::ResourceLimit);
    BOOST_CHECK(reduced.entries.empty());
    history.SetCacheBudget({0, 0, 1, entry_bytes * 2});
    BOOST_REQUIRE_EQUAL(Read(history, tip, 16).entries.size(), 2);
}

BOOST_AUTO_TEST_CASE(local_cache_options_reject_unlimited_invalid_and_overflowing_values)
{
    constexpr size_t MIB{1024 * 1024};
    const auto chosen = tides::HistoryCacheBudgetFromMiB("128", "257");
    BOOST_CHECK_EQUAL(chosen.bytes, 128 * MIB);
    BOOST_CHECK_EQUAL(chosen.query_bytes, 257 * MIB);
    BOOST_CHECK_EQUAL(chosen.blocks, 4096);
    BOOST_CHECK_EQUAL(chosen.queries, 16);
    BOOST_CHECK(tides::HistoryCacheBudgetFromMiB("64", "64") == tides::HistoryCacheBudget{});
    for (const std::string_view invalid : {"", "0", "-1", "+1", "1.5", " 1", "1 ", "unlimited", "12MiB", "18446744073709551616"}) {
        BOOST_CHECK_THROW(tides::HistoryCacheBudgetFromMiB(invalid, "64"), std::invalid_argument);
        BOOST_CHECK_THROW(tides::HistoryCacheBudgetFromMiB("64", invalid), std::invalid_argument);
    }
    const size_t maximum = std::numeric_limits<size_t>::max() / MIB;
    const auto limit = tides::HistoryCacheBudgetFromMiB(std::to_string(maximum), std::to_string(maximum));
    BOOST_CHECK_EQUAL(limit.bytes, maximum * MIB);
    BOOST_CHECK_EQUAL(limit.query_bytes, maximum * MIB);
    BOOST_CHECK_THROW(tides::HistoryCacheBudgetFromMiB(std::to_string(maximum + 1), "64"), std::invalid_argument);
    BOOST_CHECK_THROW(tides::HistoryCacheBudgetFromMiB("64", std::to_string(maximum + 1)), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(process_configuration_is_validated_and_observable_without_consensus_mutation)
{
    struct Restore {
        tides::HistoryCacheBudget old{tides::ConfiguredHistoryCacheBudget()};
        ~Restore() { tides::ConfigureHistoryCache(old); }
    } restore;
    const auto chosen = tides::HistoryCacheBudgetFromMiB("128", "257");
    tides::ConfigureHistoryCache(chosen);
    BOOST_CHECK(tides::ConfiguredHistoryCacheBudget() == chosen);
    auto invalid = chosen;
    invalid.query_bytes = 0;
    BOOST_CHECK_THROW(tides::ConfigureHistoryCache(invalid), std::invalid_argument);
    BOOST_CHECK(tides::ConfiguredHistoryCacheBudget() == chosen);
    invalid = chosen;
    invalid.queries = 0;
    BOOST_CHECK_THROW(tides::ConfigureHistoryCache(invalid), std::invalid_argument);
    BOOST_CHECK(tides::ConfiguredHistoryCacheBudget() == chosen);
}

BOOST_AUTO_TEST_CASE(wrong_local_anchor_and_callback_failures_are_not_consensus_invalidity)
{
    auto* tip = Add(nodes.front().get(), {Admit(1, 1)});
    const auto original = *deltas.at(tip->hash);
    const std::vector<std::function<void(tides::HistoryDelta&)>> damage{
        [](auto& value) { value.block_hash = Number(7); },
        [](auto& value) { value.parent_hash = Number(7); },
        [](auto& value) { value.snapshot_hash = Number(7); },
        [](auto& value) { ++value.height; },
        [](auto& value) { value.encoded_bytes = 0; },
    };
    for (const auto& mutate : damage) {
        *deltas.at(tip->hash) = original;
        mutate(*deltas.at(tip->hash));
        tides::HistoryIndex history;
        const auto result = Read(history, tip);
        BOOST_CHECK(result.status == tides::HistoryStatus::MissingData);
        BOOST_CHECK(result.entries.empty());
    }
    tides::HistoryIndex history;
    const auto unavailable = history.ReadPool(&tip->index, 1, Number(1), 8,
        [](const auto&) -> tides::DeltaResult { throw std::runtime_error("local disk read failed"); });
    BOOST_CHECK(unavailable.status == tides::HistoryStatus::MissingData);
    const auto allocation = history.ReadPool(&tip->index, 1, Number(1), 8,
        [](const auto&) -> tides::DeltaResult { throw std::bad_alloc{}; });
    BOOST_CHECK(allocation.status == tides::HistoryStatus::ResourceLimit);
    const auto invalid = history.ReadPool(&tip->index, 1, Number(1), 8,
        [](const auto&) { return tides::DeltaResult::Invalid("authenticated malformed snapshot"); });
    BOOST_CHECK(invalid.status == tides::HistoryStatus::Invalid);
}

BOOST_AUTO_TEST_CASE(authenticated_admission_shape_and_numeric_order_are_checked)
{
    auto* tip = Add(nodes.front().get(), {Admit(1, 1), Admit(2, 2)});
    const auto original = *deltas.at(tip->hash);
    const std::vector<std::function<void(tides::HistoryDelta&)>> damage{
        [](auto& value) { value.admissions[0].proof_id.SetNull(); },
        [](auto& value) { value.admissions[0].pool.SetNull(); },
        [](auto& value) { value.admissions[0].work.SetNull(); },
        [](auto& value) { value.admissions[0].payout_script = {0x51}; },
        [](auto& value) { value.admissions[0].proof_id = Number(2); },
        [](auto& value) { std::reverse(value.admissions.begin(), value.admissions.end()); },
    };
    for (const auto& mutate : damage) {
        *deltas.at(tip->hash) = original;
        mutate(*deltas.at(tip->hash));
        tides::HistoryIndex history;
        const auto result = Read(history, tip);
        BOOST_CHECK(result.status == tides::HistoryStatus::Invalid);
        BOOST_CHECK(result.entries.empty());
    }
}

BOOST_AUTO_TEST_CASE(payout_address_may_appear_in_separate_pool_histories)
{
    auto* tip = Add(nodes.front().get(), {Admit(1, 1, 8, 1), Admit(2, 1, 8, 2)});
    tides::HistoryIndex history;
    const auto a = Read(history, tip, 8, 1);
    const auto b = Read(history, tip, 8, 2);
    BOOST_REQUIRE(a.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE(b.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(a.entries.size(), 1);
    BOOST_REQUIRE_EQUAL(b.entries.size(), 1);
    BOOST_CHECK(a.entries[0].payout_script == b.entries[0].payout_script);
    BOOST_CHECK(a.entries[0].pool == Number(1));
    BOOST_CHECK(b.entries[0].pool == Number(2));
    BOOST_CHECK(a.entries[0].proof_id != b.entries[0].proof_id);
}

BOOST_AUTO_TEST_CASE(cached_delta_owns_bytes_and_cursor_survives_new_index_objects)
{
    auto* first = Add(nodes.front().get(), {Admit(1, 1)});
    auto* second = Add(first, {});
    auto* tip = Add(second, {});
    tides::HistoryIndex history;
    const auto limited = Read(history, tip, 8, 1, {1, 100, 8192});
    BOOST_REQUIRE(limited.status == tides::HistoryStatus::ResourceLimit);
    RebuildIndices();
    tip = nodes.back().get();
    const auto result = Read(history, tip);
    BOOST_REQUIRE(result.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(result.entries.size(), 1);
    // A new work request reuses the verified block delta, not the mutable
    // object retained by this test callback.
    deltas.at(nodes[1]->hash)->admissions[0].payout_script = Script(9);
    const auto cached = Read(history, tip, 7);
    BOOST_REQUIRE(cached.status == tides::HistoryStatus::Ready);
    BOOST_REQUIRE_EQUAL(cached.entries.size(), 1);
    BOOST_CHECK(cached.entries[0].payout_script == Script(1));
}

BOOST_AUTO_TEST_SUITE_END()
