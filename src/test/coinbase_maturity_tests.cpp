// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/params.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>

BOOST_AUTO_TEST_SUITE(coinbase_maturity_tests)

BOOST_AUTO_TEST_CASE(long_maturity_window_boundaries)
{
    constexpr int INT_MAX_{std::numeric_limits<int>::max()};
    constexpr int64_t INT64_MIN_{std::numeric_limits<int64_t>::min()};
    constexpr int64_t INT64_MAX_{std::numeric_limits<int64_t>::max()};

    Consensus::Params params;
    BOOST_CHECK(!params.CoinbaseMaturityLongScheduled());
    for (const int64_t mtp_prev : {INT64_MIN_, int64_t{0}, INT64_MAX_}) {
        BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(0, mtp_prev));
        BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(INT_MAX_, mtp_prev));
        BOOST_CHECK_EQUAL(params.CoinbaseMaturityLongHeldFrom(INT_MAX_, mtp_prev), INT_MAX_);
    }

    params.CoinbaseMaturityLongStartHeight = 100;
    params.CoinbaseMaturityLongEnforceHeight = 200;
    params.CoinbaseMaturityLongReleaseTime = 1000;
    BOOST_CHECK(params.CoinbaseMaturityLongScheduled());

    // The rule starts at the enforce height, whatever the time...
    BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(199, INT64_MIN_));
    BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(199, 0));
    BOOST_CHECK(params.CoinbaseMaturityLongActiveAt(200, INT64_MIN_));
    BOOST_CHECK(params.CoinbaseMaturityLongActiveAt(200, 0));
    BOOST_CHECK(params.CoinbaseMaturityLongActiveAt(200, 999));
    // ...and only the parent's median-time-past reaching the release time ends it
    BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(200, 1000));
    BOOST_CHECK(params.CoinbaseMaturityLongActiveAt(1000000, 999));
    BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(1000000, 1000));
    BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(INT_MAX_, 1001));
    BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(INT_MAX_, INT64_MAX_));

    // While active, coinbases from the start height on are held
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityLongHeldFrom(199, 0), INT_MAX_);
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityLongHeldFrom(200, 999), 100);
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityLongHeldFrom(1000000, 999), 100);
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityLongHeldFrom(200, 1000), INT_MAX_);
}

BOOST_AUTO_TEST_CASE(long_maturity_schedules)
{
    constexpr int INT_MAX_{std::numeric_limits<int>::max()};

    const auto main{CChainParams::Main()};
    const auto testnet4{CChainParams::TestNet4()};
    for (const auto* params : {main.get(), testnet4.get()}) {
        const auto& consensus{params->GetConsensus()};
        BOOST_CHECK(consensus.CoinbaseMaturityLongScheduled());
        BOOST_CHECK_LE(consensus.CoinbaseMaturityLongStartHeight, consensus.CoinbaseMaturityLongEnforceHeight);
        // Released when RDTS expires, at whatever height that turns out to be
        BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongReleaseTime, consensus.RdtsExpiryTime);
        BOOST_CHECK_GT(consensus.CoinbaseMaturityLongReleaseTime, 0);
        BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(consensus.CoinbaseMaturityLongEnforceHeight - 1, 0));
        BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(consensus.CoinbaseMaturityLongEnforceHeight, consensus.RdtsExpiryTime - 1));
        BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(INT_MAX_, consensus.RdtsExpiryTime - 1));
        BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(consensus.CoinbaseMaturityLongEnforceHeight, consensus.RdtsExpiryTime));
        BOOST_REQUIRE_EQUAL(consensus.chainstate_revalidation_deployments.size(), 1);
        const auto& deployment{consensus.chainstate_revalidation_deployments.front()};
        BOOST_CHECK_EQUAL(deployment.name, "long_coinbase_maturity");
        BOOST_CHECK_EQUAL(deployment.start_height, consensus.CoinbaseMaturityLongEnforceHeight);
        BOOST_CHECK_EQUAL(deployment.stop_height, INT_MAX_);
    }

    const auto regtest_default{CChainParams::RegTest({})};
    const auto& default_consensus{regtest_default->GetConsensus()};
    BOOST_CHECK(!default_consensus.CoinbaseMaturityLongScheduled());
    BOOST_CHECK(!default_consensus.CoinbaseMaturityLongActiveAt(0, 0));
    BOOST_CHECK(default_consensus.chainstate_revalidation_deployments.empty());

    CChainParams::RegTestOptions options;
    options.coinbase_maturity_long_start_height = 10;
    options.coinbase_maturity_long_enforce_height = 20;
    options.coinbase_maturity_long_release_time = 5000;
    const auto regtest{CChainParams::RegTest(options)};
    const auto& consensus{regtest->GetConsensus()};
    BOOST_CHECK(consensus.CoinbaseMaturityLongScheduled());
    BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongStartHeight, 10);
    BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongEnforceHeight, 20);
    BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongReleaseTime, 5000);
    BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(19, 0));
    BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(20, 4999));
    BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(20, 5000));
    BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(1000000, 4999));
    BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(1000000, 5000));
    BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongHeldFrom(20, 4999), 10);
    BOOST_REQUIRE_EQUAL(consensus.chainstate_revalidation_deployments.size(), 1);
    const auto& deployment{consensus.chainstate_revalidation_deployments.front()};
    BOOST_CHECK_EQUAL(deployment.name, "long_coinbase_maturity");
    BOOST_CHECK_EQUAL(deployment.start_height, 20);
    BOOST_CHECK_EQUAL(deployment.stop_height, INT_MAX_);
}

BOOST_AUTO_TEST_SUITE_END()
