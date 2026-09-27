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
    params.coinbase_maturity_long_periods = {{100, INT_MAX_}};
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
        // The last period is released when RDTS expires
        BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongReleaseTime, consensus.RdtsExpiryTime);
        BOOST_CHECK_GT(consensus.CoinbaseMaturityLongReleaseTime, 0);
        BOOST_REQUIRE_EQUAL(consensus.coinbase_maturity_long_periods.size(), 4);
        BOOST_CHECK_EQUAL(consensus.coinbase_maturity_long_periods.front().start_height, consensus.CoinbaseMaturityLongStartHeight);
        BOOST_CHECK_EQUAL(consensus.coinbase_maturity_long_periods.back().release_height, INT_MAX_);
        BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(consensus.CoinbaseMaturityLongEnforceHeight - 1, 0));
        BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(consensus.CoinbaseMaturityLongEnforceHeight, 0));
        // RDTS expiry does not release coinbases before the first period's release height
        const int first_release{consensus.CoinbaseMaturityLongFirstReleaseHeight()};
        BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongHeldFrom(first_release - 1, consensus.RdtsExpiryTime), consensus.CoinbaseMaturityLongStartHeight);
        BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(INT_MAX_, consensus.RdtsExpiryTime - 1));
        BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(INT_MAX_, consensus.RdtsExpiryTime));
        BOOST_REQUIRE_EQUAL(consensus.chainstate_revalidation_deployments.size(), 1);
        const auto& deployment{consensus.chainstate_revalidation_deployments.front()};
        BOOST_CHECK_EQUAL(deployment.name, "long_coinbase_maturity");
        BOOST_CHECK_EQUAL(deployment.start_height, consensus.CoinbaseMaturityLongEnforceHeight);
        // Finite, and after the enforce height: a missing stop would rewind a
        // late upgrade from whatever its tip is.
        BOOST_CHECK_GT(deployment.stop_height, consensus.CoinbaseMaturityLongEnforceHeight);
        BOOST_CHECK_LT(deployment.stop_height, INT_MAX_);
    }

    // Checkpoint block 908765, median time past 1754416682.
    BOOST_CHECK_EQUAL(main->GetConsensus().chainstate_revalidation_deployments.front().stop_height,
                      Consensus::LastHeightWithParentMtpBelow(908765, 1754416682, main->GetConsensus().RdtsExpiryTime));
    BOOST_CHECK_EQUAL(testnet4->GetConsensus().chainstate_revalidation_deployments.front().stop_height,
                      Consensus::LastHeightWithParentMtpBelow(0, testnet4->GenesisBlock().nTime, testnet4->GetConsensus().RdtsExpiryTime));

    const auto& mainnet{main->GetConsensus()};
    // 45 days, 105 days, 105 days, then whatever blocks remain until RDTS.
    // 144 blocks/day at the 10-minute target.
    BOOST_REQUIRE_EQUAL(mainnet.coinbase_maturity_long_periods.size(), 4);
    BOOST_CHECK_EQUAL(mainnet.coinbase_maturity_long_periods[0].start_height, 973440);
    BOOST_CHECK_EQUAL(mainnet.coinbase_maturity_long_periods[0].release_height, 979920);
    BOOST_CHECK_EQUAL(mainnet.coinbase_maturity_long_periods[1].start_height, 979920);
    BOOST_CHECK_EQUAL(mainnet.coinbase_maturity_long_periods[1].release_height, 995040);
    BOOST_CHECK_EQUAL(mainnet.coinbase_maturity_long_periods[2].start_height, 995040);
    BOOST_CHECK_EQUAL(mainnet.coinbase_maturity_long_periods[2].release_height, 1010160);
    BOOST_CHECK_EQUAL(mainnet.coinbase_maturity_long_periods[3].start_height, 1010160);
    BOOST_CHECK_EQUAL(mainnet.coinbase_maturity_long_periods[3].release_height, INT_MAX_);
    BOOST_CHECK_EQUAL(mainnet.CoinbaseMaturityLongHeldFrom(979919, 0), 973440);
    BOOST_CHECK_EQUAL(mainnet.CoinbaseMaturityLongHeldFrom(979920, 0), 979920);
    BOOST_CHECK_EQUAL(mainnet.CoinbaseMaturityLongHeldFrom(995039, 0), 979920);
    BOOST_CHECK_EQUAL(mainnet.CoinbaseMaturityLongHeldFrom(995040, 0), 995040);
    BOOST_CHECK_EQUAL(mainnet.CoinbaseMaturityLongHeldFrom(1010159, 0), 995040);
    BOOST_CHECK_EQUAL(mainnet.CoinbaseMaturityLongHeldFrom(1010160, mainnet.RdtsExpiryTime - 1), 1010160);
    BOOST_CHECK_EQUAL(mainnet.CoinbaseMaturityLongHeldFrom(2000000, mainnet.RdtsExpiryTime), INT_MAX_);

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
    BOOST_REQUIRE_EQUAL(consensus.coinbase_maturity_long_periods.size(), 1);
    BOOST_CHECK_EQUAL(consensus.coinbase_maturity_long_periods.front().start_height, 10);
    BOOST_CHECK_EQUAL(consensus.coinbase_maturity_long_periods.front().release_height, INT_MAX_);
    BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(19, 0));
    BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(20, 4999));
    BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(20, 5000));
    BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(1000000, 4999));
    BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(1000000, 5000));
    BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongHeldFrom(20, 4999), 10);
    // Release is before the genesis median time past, so no block on this
    // chain can be under the rule and there is nothing to rewind.
    BOOST_CHECK(consensus.chainstate_revalidation_deployments.empty());

    CChainParams::RegTestOptions future;
    future.coinbase_maturity_long_start_height = 10;
    future.coinbase_maturity_long_enforce_height = 20;
    future.coinbase_maturity_long_release_time = regtest->GenesisBlock().nTime + 1000;
    const auto future_params{CChainParams::RegTest(future)};
    const auto& future_consensus{future_params->GetConsensus()};
    BOOST_REQUIRE_EQUAL(future_consensus.chainstate_revalidation_deployments.size(), 1);
    const auto& deployment{future_consensus.chainstate_revalidation_deployments.front()};
    BOOST_CHECK_EQUAL(deployment.name, "long_coinbase_maturity");
    BOOST_CHECK_EQUAL(deployment.start_height, 20);
    BOOST_CHECK_EQUAL(deployment.stop_height, Consensus::LastHeightWithParentMtpBelow(0, regtest->GenesisBlock().nTime, future.coinbase_maturity_long_release_time));
    BOOST_CHECK_GT(deployment.stop_height, deployment.start_height);
}

BOOST_AUTO_TEST_CASE(mtp_bound_on_revalidation_stop)
{
    constexpr int INT_MAX_{std::numeric_limits<int>::max()};
    BOOST_CHECK_EQUAL(Consensus::LastHeightWithParentMtpBelow(100, 1000, 1000), 100);
    BOOST_CHECK_EQUAL(Consensus::LastHeightWithParentMtpBelow(100, 1000, 999), 100);
    // One second of median time past takes six blocks. Three seconds is 18.
    BOOST_CHECK_EQUAL(Consensus::LastHeightWithParentMtpBelow(100, 1000, 1003), 118);
    BOOST_CHECK_EQUAL(Consensus::LastHeightWithParentMtpBelow(0, 0, int64_t{INT_MAX_}), INT_MAX_);
}

BOOST_AUTO_TEST_SUITE_END()
