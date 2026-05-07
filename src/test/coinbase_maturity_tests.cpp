// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

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
    const auto testnet4{CChainParams::TestNet4()};
    {
        const auto& consensus{testnet4->GetConsensus()};
        BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLong, consensus.CoinbaseMaturityLongReleaseHeight - consensus.CoinbaseMaturityLongStartHeight);
        BOOST_CHECK_GT(consensus.CoinbaseMaturityLong, COINBASE_MATURITY);
        // Other rules may add their own revalidation deployments (testnet4 has
        // one for the RDTS extension), so look this one up by name.
        const auto& deployments{consensus.chainstate_revalidation_deployments};
        const auto deployment_it{std::find_if(deployments.begin(), deployments.end(),
                                              [](const auto& d) { return d.name == "long_coinbase_maturity"; })};
        BOOST_REQUIRE(deployment_it != deployments.end());
        BOOST_CHECK_EQUAL(deployment_it->start_height, consensus.CoinbaseMaturityLongEnforceHeight);
        BOOST_CHECK_EQUAL(deployment_it->stop_height, consensus.CoinbaseMaturityLongReleaseHeight - 1);
    }

    const auto& main_consensus{main->GetConsensus()};
    BOOST_CHECK_EQUAL(main_consensus.CoinbaseMaturityLong, 25920);
    BOOST_CHECK_EQUAL(main_consensus.CoinbaseMaturityLongStartHeight, 979919);
    BOOST_CHECK_EQUAL(main_consensus.RdtsExpiryTime, 1819756800);
    BOOST_CHECK(main_consensus.CoinbaseMaturityLongUntilRdts);
    BOOST_CHECK(!main_consensus.CoinbaseMaturityLongActiveAt(979918));
    BOOST_CHECK(main_consensus.CoinbaseMaturityLongActiveAt(979919));
    BOOST_CHECK(main_consensus.CoinbaseMaturityLongActiveAt(979920));
    BOOST_CHECK_EQUAL(main_consensus.CoinbaseMaturityLongEnforceHeight, 979919);
    BOOST_REQUIRE_EQUAL(main_consensus.chainstate_revalidation_deployments.size(), 2);
    BOOST_CHECK_EQUAL(main_consensus.chainstate_revalidation_deployments[1].name, "rolling_coinbase_maturity_180d_v2");
    BOOST_CHECK_EQUAL(main_consensus.chainstate_revalidation_deployments[1].start_height, 979919);
    BOOST_CHECK_EQUAL(main_consensus.chainstate_revalidation_deployments[1].stop_height, std::numeric_limits<int>::max());

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

    options.coinbase_maturity_long_expiry = 1819756800;
    const auto rolling{CChainParams::RegTest(options)};
    const auto& rolling_consensus{rolling->GetConsensus()};
    BOOST_CHECK_EQUAL(rolling_consensus.CoinbaseMaturityLong, 140);
    BOOST_CHECK(rolling_consensus.CoinbaseMaturityLongActiveAt(150));
    BOOST_CHECK(rolling_consensus.CoinbaseMaturityLongUntilRdts);
    BOOST_CHECK_EQUAL(rolling_consensus.RdtsExpiryTime, 1819756800);
}

BOOST_FIXTURE_TEST_CASE(rolling_maturity_mining_parent_mtp, BasicTestingSetup)
{
    Consensus::Params params;
    params.CoinbaseMaturityLongUntilRdts = true;
    params.CoinbaseMaturityLong = 25920;
    params.RdtsExpiryTime = 1000;
    std::vector<CBlockIndex> blocks(30);
    for (int i = 0; i < 30; ++i) {
        blocks[i].nHeight = i;
        blocks[i].nTime = 980 + i;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].BuildSkip();
    }
    // Block 25 has MTP exactly at expiry, but its own reward is covered.
    BOOST_CHECK_EQUAL(blocks[24].GetMedianTimePast(), 999);
    BOOST_CHECK_EQUAL(blocks[25].GetMedianTimePast(), 1000);
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityLongEndHeight(params, &blocks[24]), std::numeric_limits<int>::max());
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityLongEndHeight(params, &blocks[25]), 26);
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityLongEndHeight(params, &blocks[29]), 26);
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &blocks[25]), 25920);
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &blocks[26]), 100);
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, nullptr), 25920);

    // Test actual input validation at both depths, including a single transaction
    // spending rewards on opposite sides of the mining-time expiry boundary.
    CCoinsView base;
    CCoinsViewCache view{&base};
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vout.emplace_back(1, CScript{});
    for (int i = 0; i < 2; ++i) {
        tx.vin[i].prevout = COutPoint{Txid::FromUint256(uint256::ONE), static_cast<uint32_t>(i)};
        view.AddCoin(tx.vin[i].prevout, Coin{CTxOut{1, CScript{}}, 25 + i, true}, false);
    }
    auto check = [&](const CMutableTransaction& spend, int height, int start = 0) {
        TxValidationState state;
        CAmount fee;
        return Consensus::CheckTxInputs(CTransaction{spend}, state, view, height, fee,
            CheckTxInputsRules::None, 25920, start, 26);
    };
    BOOST_CHECK(!check(tx, 25 + 25919));
    BOOST_CHECK(check(tx, 25 + 25920));
    auto post_expiry{tx};
    post_expiry.vin.erase(post_expiry.vin.begin());
    BOOST_CHECK(!check(post_expiry, 26 + 99));
    BOOST_CHECK(check(post_expiry, 26 + 100));
    auto pre_expiry{tx};
    pre_expiry.vin.pop_back();
    BOOST_CHECK(!check(pre_expiry, 25 + 100));
    BOOST_CHECK(check(pre_expiry, 25 + 100, 26)); // pre-activation reward

    // Reorg to a branch that has not expired: the same height remains covered.
    blocks[20].nTime = 999;
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityLongEndHeight(params, &blocks[25]), std::numeric_limits<int>::max());
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &blocks[26]), 25920);
}

BOOST_FIXTURE_TEST_CASE(mainnet_later_activation_preserves_history, BasicTestingSetup)
{
    const auto main{CChainParams::Main()};
    const auto& params{main->GetConsensus()};
    BOOST_CHECK_EQUAL(params.chainstate_revalidation_deployments[0].name, "long_coinbase_maturity");
    BOOST_CHECK_EQUAL(params.chainstate_revalidation_deployments[0].start_height, 973440);
    BOOST_CHECK_EQUAL(params.chainstate_revalidation_deployments[0].stop_height, 979919);

    auto check = [&](int coin_height, int spend_height) {
        CCoinsView base;
        CCoinsViewCache view{&base};
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        tx.vout.emplace_back(1, CScript{});
        view.AddCoin(tx.vin[0].prevout, Coin{CTxOut{1, CScript{}}, coin_height, true}, false);
        TxValidationState state;
        CAmount fee;
        return Consensus::CheckTxInputs(CTransaction{tx}, state, view, spend_height, fee, CheckTxInputsRules::None, params);
    };
    // Preserve the old rule, including its overlap with activation at 979919.
    BOOST_CHECK(check(973439, 973539));
    BOOST_CHECK(!check(973440, 973540));
    BOOST_CHECK(!check(973440, 979918));
    BOOST_CHECK(!check(973440, 979919));
    BOOST_CHECK(check(973440, 979920));
    BOOST_CHECK(check(979820, 979920));
    BOOST_CHECK(!check(979918, 979918 + 99));
    BOOST_CHECK(check(979918, 979918 + 100));
    BOOST_CHECK(!check(979919, 979919 + 100));
    BOOST_CHECK(!check(979919, 979919 + 25919));
    BOOST_CHECK(check(979919, 979919 + 25920));
    BOOST_CHECK(!check(979920, 979920 + 25919));
    BOOST_CHECK(check(979920, 979920 + 25920));

    CBlockIndex parent;
    parent.nTime = params.RdtsExpiryTime - 1;
    CBlockIndex reward;
    reward.pprev = &parent;
    reward.nHeight = 979918;
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &reward), 6480);
    reward.nHeight = 979919;
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &reward), 25920);
    parent.nTime = params.RdtsExpiryTime;
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &reward), 100);
}

BOOST_AUTO_TEST_SUITE_END()
