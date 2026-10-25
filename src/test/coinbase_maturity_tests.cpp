// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <uint256.h>


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
    const auto testnet4{CChainParams::TestNet4()};
    for (const auto* params : {main.get(), testnet4.get()}) {
        const auto& consensus{params->GetConsensus()};
        BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLong, consensus.CoinbaseMaturityLongReleaseHeight - consensus.CoinbaseMaturityLongStartHeight);
        BOOST_CHECK_GT(consensus.CoinbaseMaturityLong, COINBASE_MATURITY);
        BOOST_REQUIRE_EQUAL(consensus.chainstate_revalidation_deployments.size(), 1);
        const auto& deployment{consensus.chainstate_revalidation_deployments.front()};
        BOOST_CHECK_EQUAL(deployment.name, "long_coinbase_maturity");
        BOOST_CHECK_EQUAL(deployment.start_height, consensus.CoinbaseMaturityLongEnforceHeight);
        BOOST_CHECK_EQUAL(deployment.stop_height, consensus.CoinbaseMaturityLongReleaseHeight - 1);
    }

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

BOOST_AUTO_TEST_CASE(historical_window_lock_sticks)
{
    const auto main{CChainParams::Main()};
    const auto& params{main->GetConsensus()};

    auto check = [&](int coin_height, int spend_height) {
        CCoinsView base;
        CCoinsViewCache view{&base};
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        tx.vout.emplace_back(1, CScript{});
        view.AddCoin(tx.vin[0].prevout, Coin{CTxOut{1, CScript{}}, coin_height, true}, false);
        TxValidationState state;
        CAmount fee{0};
        // Simulate spend after the temporary window has closed.
        return Consensus::CheckTxInputs(CTransaction{tx}, state, view, spend_height, fee,
                                        CheckTxInputsRules::None, params.CoinbaseMaturityLong,
                                        std::numeric_limits<int>::max());
    };

    // Coins created in the original window still require 6480 after 979920.
    BOOST_CHECK(!check(973440, 979919));
    BOOST_CHECK(check(973440, 979920));           // 973440 + 6480
    BOOST_CHECK(!check(973450, 979929));          // not yet
    BOOST_CHECK(check(973450, 979930));           // exactly mature
    BOOST_CHECK(!check(979919, 979919 + 6479));
    BOOST_CHECK(check(979919, 979919 + 6480));
    // Coins created after the window stay at 100.
    BOOST_CHECK(check(979920, 979920 + 100));
}

BOOST_AUTO_TEST_SUITE_END()
