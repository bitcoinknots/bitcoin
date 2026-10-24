// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_AUTO_TEST_SUITE(coinbase_maturity_tests)

BOOST_AUTO_TEST_CASE(long_maturity_window_boundaries)
{
    Consensus::Params params;
    params.CoinbaseMaturityLongEnforceHeight = 200;
    params.CoinbaseMaturityLongReleaseHeight = 300;

    BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(199));
    BOOST_CHECK(params.CoinbaseMaturityLongActiveAt(200));
    BOOST_CHECK(params.CoinbaseMaturityLongActiveAt(299));
    BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(300));
    BOOST_CHECK(!params.CoinbaseMaturityLongActiveAt(std::numeric_limits<int>::max()));
}

BOOST_AUTO_TEST_CASE(long_maturity_derived_from_schedule)
{
    const auto main{CChainParams::Main()};
    const auto& main_consensus{main->GetConsensus()};
    BOOST_CHECK_EQUAL(main_consensus.CoinbaseMaturityLong, 6480);
    BOOST_CHECK_EQUAL(main_consensus.CoinbaseMaturityLongReleaseHeight, std::numeric_limits<int>::max());
    BOOST_REQUIRE_EQUAL(main_consensus.chainstate_revalidation_deployments.size(), 1);
    const auto& main_deployment{main_consensus.chainstate_revalidation_deployments.front()};
    BOOST_CHECK_EQUAL(main_deployment.name, "long_coinbase_maturity");
    BOOST_CHECK_EQUAL(main_deployment.start_height, main_consensus.CoinbaseMaturityLongEnforceHeight);
    BOOST_CHECK_EQUAL(main_deployment.stop_height, main_consensus.CoinbaseMaturityLongReleaseHeight - 1);

    const auto testnet4{CChainParams::TestNet4()};
    const auto& test_consensus{testnet4->GetConsensus()};
    BOOST_CHECK_EQUAL(test_consensus.CoinbaseMaturityLong, test_consensus.CoinbaseMaturityLongReleaseHeight - test_consensus.CoinbaseMaturityLongStartHeight);
    BOOST_CHECK_GT(test_consensus.CoinbaseMaturityLong, COINBASE_MATURITY);
    BOOST_REQUIRE_EQUAL(test_consensus.chainstate_revalidation_deployments.size(), 1);
    const auto& test_deployment{test_consensus.chainstate_revalidation_deployments.front()};
    BOOST_CHECK_EQUAL(test_deployment.name, "long_coinbase_maturity");
    BOOST_CHECK_EQUAL(test_deployment.start_height, test_consensus.CoinbaseMaturityLongEnforceHeight);
    BOOST_CHECK_EQUAL(test_deployment.stop_height, test_consensus.CoinbaseMaturityLongReleaseHeight - 1);

    const auto regtest_default{CChainParams::RegTest({})};
    const auto& default_consensus{regtest_default->GetConsensus()};
    BOOST_CHECK_EQUAL(default_consensus.CoinbaseMaturityLong, COINBASE_MATURITY);
    BOOST_CHECK(!default_consensus.CoinbaseMaturityLongActiveAt(0));
    BOOST_CHECK(default_consensus.chainstate_revalidation_deployments.empty());

    CChainParams::RegTestOptions options;
    options.coinbase_maturity_long_start_height = 10;
    options.coinbase_maturity_long_enforce_height = 20;
    options.coinbase_maturity_long_release_height = 150;
    const auto regtest{CChainParams::RegTest(options)};
    const auto& consensus{regtest->GetConsensus()};
    BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLong, 140);
    BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(19));
    BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(20));
    BOOST_CHECK(consensus.CoinbaseMaturityLongActiveAt(149));
    BOOST_CHECK(!consensus.CoinbaseMaturityLongActiveAt(150));
    BOOST_REQUIRE_EQUAL(consensus.chainstate_revalidation_deployments.size(), 1);
    const auto& deployment{consensus.chainstate_revalidation_deployments.front()};
    BOOST_CHECK_EQUAL(deployment.name, "long_coinbase_maturity");
    BOOST_CHECK_EQUAL(deployment.start_height, 20);
    BOOST_CHECK_EQUAL(deployment.stop_height, 149);
}

BOOST_AUTO_TEST_SUITE_END()
