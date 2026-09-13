// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/retry_worker.h>
#include <sharepool/hash_store.h>
#include <sharepool/hash_validation_cache.h>
#include <sharepool/mining_budget.h>
#include <arith_uint256.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <limits>
#include <stdexcept>
#include <thread>

using namespace std::chrono_literals;

BOOST_AUTO_TEST_SUITE(sharepool_retry_worker_tests)

BOOST_AUTO_TEST_CASE(signals_during_a_pass_are_coalesced_but_not_lost)
{
    std::promise<void> entered, release, second;
    auto entered_future = entered.get_future();
    auto release_future = release.get_future();
    auto second_future = second.get_future();
    std::atomic<int> calls{0};
    const auto caller = std::this_thread::get_id();
    std::atomic<bool> different_thread{false};
    sharepool::RetryWorker worker{[&](const std::atomic<bool>&) {
        different_thread = std::this_thread::get_id() != caller;
        if (++calls == 1) {
            entered.set_value();
            release_future.wait();
        } else {
            second.set_value();
        }
    }, {}, 0ms, 0};
    BOOST_REQUIRE(worker.Request()); // Pre-start notifications survive startup.
    worker.Start();
    const bool started = entered_future.wait_for(5s) == std::future_status::ready;
    if (!started) release.set_value();
    BOOST_REQUIRE(started);
    for (int count{0}; count < 1000; ++count) BOOST_CHECK(worker.Request());
    BOOST_CHECK(worker.Stats().active);
    BOOST_CHECK(worker.Stats().pending);
    BOOST_CHECK_EQUAL(worker.Stats().requests, 1001U);
    release.set_value();
    BOOST_CHECK(second_future.wait_for(5s) == std::future_status::ready);
    worker.Stop();
    BOOST_CHECK(different_thread);
    BOOST_CHECK_EQUAL(calls, 2);
    BOOST_CHECK_EQUAL(worker.Stats().passes, 2U);
    BOOST_CHECK(!worker.Stats().pending);
    BOOST_CHECK(!worker.Stats().active);
}

BOOST_AUTO_TEST_CASE(shutdown_stops_active_work_and_discards_a_queued_notification)
{
    std::promise<void> entered;
    auto entered_future = entered.get_future();
    std::atomic<bool> interrupted{false};
    std::atomic<int> calls{0};
    sharepool::RetryWorker worker{[&](const std::atomic<bool>& stopping) {
        ++calls;
        entered.set_value();
        while (!stopping) std::this_thread::sleep_for(1ms);
        interrupted = true;
    }, {}, 0ms, 0};
    worker.Start();
    BOOST_REQUIRE(worker.Request());
    BOOST_REQUIRE(entered_future.wait_for(5s) == std::future_status::ready);
    BOOST_REQUIRE(worker.Request());
    worker.Stop();
    BOOST_CHECK(interrupted);
    BOOST_CHECK_EQUAL(calls, 1);
    BOOST_CHECK(worker.Stats().stopping);
    BOOST_CHECK(!worker.Stats().pending);
    BOOST_CHECK(!worker.Request());
    worker.Stop(); // Lifecycle cleanup is idempotent.
}

BOOST_AUTO_TEST_CASE(shutdown_before_start_never_launches_work)
{
    std::atomic<int> calls{0};
    sharepool::RetryWorker worker{[&](const std::atomic<bool>&) { ++calls; }, {}};
    BOOST_REQUIRE(worker.Request());
    worker.Stop();
    worker.Start();
    BOOST_CHECK(!worker.Stats().started);
    BOOST_CHECK(!worker.Stats().pending);
    BOOST_CHECK(!worker.Request());
    BOOST_CHECK_EQUAL(calls, 0);
}

BOOST_AUTO_TEST_CASE(local_worker_failure_keeps_the_worker_available_for_a_later_signal)
{
    std::promise<void> failed, recovered;
    auto failed_future = failed.get_future();
    auto recovered_future = recovered.get_future();
    std::atomic<int> calls{0};
    std::atomic<bool> inspected_without_locking{false};
    sharepool::RetryWorker* instance{nullptr};
    sharepool::RetryWorker worker{[&](const std::atomic<bool>&) {
        inspected_without_locking = instance->Stats().active;
        if (++calls == 1) throw std::runtime_error{"fixture storage failure"};
        recovered.set_value();
    }, [&](std::exception_ptr) { failed.set_value(); }, 0ms, 0};
    instance = &worker;
    worker.Start();
    BOOST_REQUIRE(worker.Request());
    BOOST_REQUIRE(failed_future.wait_for(5s) == std::future_status::ready);
    BOOST_REQUIRE(worker.Request());
    BOOST_CHECK(recovered_future.wait_for(5s) == std::future_status::ready);
    worker.Stop();
    BOOST_CHECK(inspected_without_locking);
    BOOST_CHECK_EQUAL(worker.Stats().passes, 2U);
    BOOST_CHECK_EQUAL(worker.Stats().failures, 1U);
}

BOOST_FIXTURE_TEST_CASE(native_reward_cache_retains_a_warmed_graph_under_eviction_pressure, BasicTestingSetup)
{
    LOCK(cs_main);
    sharepool::HashSnapshotStore store{fs::path{}, true};
    for (uint32_t i{0}; i < 4096; ++i) store.SetNativeValidated(ArithToUint256(arith_uint256{i}), i);
    // A maximum-sized graph walks its 2048 bodies, then unrelated requests fill
    // the remainder. Lexical eviction discarded this entire freshly warm graph.
    for (uint32_t i{0}; i < 2048; ++i) BOOST_REQUIRE(store.NativeValidated(ArithToUint256(arith_uint256{i})));
    for (uint32_t i{4096}; i < 6144; ++i) store.SetNativeValidated(ArithToUint256(arith_uint256{i}), i);
    for (uint32_t i{0}; i < 2048; ++i) {
        const auto reward = store.NativeValidated(ArithToUint256(arith_uint256{i}));
        BOOST_REQUIRE(reward);
        BOOST_CHECK_EQUAL(*reward, i);
    }
    BOOST_CHECK(!store.NativeValidated(ArithToUint256(arith_uint256{2048})));
}

BOOST_AUTO_TEST_CASE(native_cache_identity_binds_witness_order_coinbase_and_header)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vout.emplace_back(50, CScript{} << OP_TRUE);
    CMutableTransaction spend;
    spend.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    spend.vin[0].scriptWitness.stack = {{1, 2, 3}};
    spend.vout.emplace_back(20, CScript{} << OP_TRUE);
    CBlock block;
    block.m_header_v2 = true;
    block.m_txcount = 2;
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(spend)};
    const auto identity = sharepool::NativeBodyCacheKey(block);
    CBlock copy{block};
    copy.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(spend)};
    BOOST_CHECK_EQUAL(sharepool::NativeBodyCacheKey(copy), identity);

    // A witness-only substitution leaves the transaction ID and header alone.
    spend.vin[0].scriptWitness.stack[0].push_back(4);
    copy.vtx[1] = MakeTransactionRef(spend);
    BOOST_CHECK_EQUAL(copy.vtx[1]->GetHash(), block.vtx[1]->GetHash());
    BOOST_CHECK(sharepool::NativeBodyCacheKey(copy) != identity);
    copy = block;
    std::swap(copy.vtx[0], copy.vtx[1]);
    BOOST_CHECK(sharepool::NativeBodyCacheKey(copy) != identity);
    copy = block;
    copy.vtx.push_back(block.vtx[1]);
    BOOST_CHECK(sharepool::NativeBodyCacheKey(copy) != identity);
    copy = block;
    coinbase.vout[0].nValue++;
    copy.vtx[0] = MakeTransactionRef(coinbase);
    BOOST_CHECK(sharepool::NativeBodyCacheKey(copy) != identity);

    // Cache keys retain fields deliberately normalized by mining template IDs.
    const auto changed = [&](auto mutate) {
        CBlock alternative{block};
        mutate(alternative);
        BOOST_CHECK(sharepool::NativeBodyCacheKey(alternative) != identity);
    };
    changed([](CBlock& b) { b.nVersion++; });
    changed([](CBlock& b) { b.hashPrevBlock = uint256::ONE; });
    changed([](CBlock& b) { b.hashMerkleRoot = uint256::ONE; });
    changed([](CBlock& b) { b.nTime++; });
    changed([](CBlock& b) { b.nBits++; });
    changed([](CBlock& b) { b.nNonce++; });
    changed([](CBlock& b) { b.m_nonce2++; });
    changed([](CBlock& b) { b.m_nonce3++; });
    changed([](CBlock& b) { b.m_extranonce.begin()[0] = 1; });
    changed([](CBlock& b) { b.m_time_offset++; });
    changed([](CBlock& b) { b.m_txcount++; });
    changed([](CBlock& b) { b.m_flags++; });
    changed([](CBlock& b) { b.m_xor_key_mask_clear_bits++; });
    changed([](CBlock& b) { b.m_xor_key.begin()[0] = 1; });
    changed([](CBlock& b) { b.m_height++; });
    changed([](CBlock& b) { b.m_mm_rhs = uint256::ONE; });
    copy = block;
    copy.vtx[1].reset();
    BOOST_CHECK_THROW(sharepool::NativeBodyCacheKey(copy), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(payout_reservation_rejects_contextual_weight_excess_before_assembly)
{
    // 6,500 P2WPKH outputs fit the ordinary weight limit, but not RDTS.
    const auto ordinary = sharepool::ReserveCoinbasePayouts(6500 * 31, false);
    BOOST_REQUIRE(ordinary);
    BOOST_CHECK(ordinary->weight <= MAX_BLOCK_WEIGHT);
    BOOST_CHECK(!sharepool::ReserveCoinbasePayouts(6500 * 31, true));
    for (const bool reduced : {false, true}) {
        const size_t limit = reduced ? REDUCED_DATA_MAX_BLOCK_WEIGHT : MAX_BLOCK_WEIGHT;
        const size_t maximum_outputs = (limit - 36) / WITNESS_SCALE_FACTOR - 379;
        const auto boundary = sharepool::ReserveCoinbasePayouts(maximum_outputs, reduced);
        BOOST_REQUIRE(boundary);
        BOOST_CHECK_EQUAL(boundary->weight, limit);
        BOOST_CHECK(boundary->serialized_bytes <= MAX_BLOCK_SERIALIZED_SIZE);
        BOOST_CHECK(!sharepool::ReserveCoinbasePayouts(maximum_outputs + 1, reduced));
        BOOST_CHECK(!sharepool::ReserveCoinbasePayouts(std::numeric_limits<size_t>::max(), reduced));
    }
}

BOOST_AUTO_TEST_SUITE_END()
