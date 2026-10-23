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
#include <validation.h>

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
    BOOST_REQUIRE_EQUAL(main_consensus.chainstate_revalidation_deployments.size(), 3);
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
    // From 995000 the rolling rule holds these rewards for a full year.
    BOOST_CHECK(!check(979919, 979919 + 25920));
    BOOST_CHECK(check(979919, 979919 + 52560));
    BOOST_CHECK(!check(979920, 979920 + 25919));
    BOOST_CHECK(!check(979920, 979920 + 25920));
    BOOST_CHECK(check(979920, 979920 + 52560));

    CBlockIndex parent;
    parent.nTime = params.RdtsExpiryTime - 1;
    CBlockIndex reward;
    reward.pprev = &parent;
    reward.nHeight = 979918;
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &reward), 6480);
    reward.nHeight = 979919;
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &reward), 52560);
    // The rolling rule ignores RDTS: a reward mined after expiry is still covered.
    parent.nTime = params.RdtsExpiryTime;
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &reward), 52560);
    reward.nHeight = 6930000;
    BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &reward), 100);
}

namespace {
//! Whether one input spending a coinbase mined at coin_height is valid in a block at spend_height.
bool SpendOk(const Consensus::Params& params, int coin_height, int spend_height,
             int long_maturity_end_height = std::numeric_limits<int>::max())
{
    CCoinsView base;
    CCoinsViewCache view{&base};
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(1, CScript{});
    view.AddCoin(tx.vin[0].prevout, Coin{CTxOut{1, CScript{}}, coin_height, true}, false);
    TxValidationState state;
    CAmount fee;
    return Consensus::CheckTxInputs(CTransaction{tx}, state, view, spend_height, fee, CheckTxInputsRules::None, params,
                                    long_maturity_end_height);
}

//! Mainnet consensus without the rolling rule, as deployed by #468.
Consensus::Params WithoutRolling(Consensus::Params params)
{
    params.CoinbaseMaturityRollingActivationHeight = std::numeric_limits<int>::max();
    return params;
}
} // namespace

BOOST_FIXTURE_TEST_CASE(rolling_maturity_mainnet_schedule, BasicTestingSetup)
{
    const auto main{CChainParams::Main()};
    const auto& params{main->GetConsensus()};
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityRolling, 52560);
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityRollingStartHeight, 979919);
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityRollingActivationHeight, 995000);
    BOOST_CHECK(!params.CoinbaseMaturityRollingActiveAt(994999));
    BOOST_CHECK(params.CoinbaseMaturityRollingActiveAt(995000));
    // Activation must come before any covered reward reaches #468's depth.
    BOOST_CHECK_LE(params.CoinbaseMaturityRollingActivationHeight,
                   params.CoinbaseMaturityRollingStartHeight + params.CoinbaseMaturityLong);

    // Coverage ends at the first block without subsidy, derived here rather than trusted.
    const int end{params.CoinbaseMaturityRollingEndHeight};
    BOOST_CHECK_EQUAL(end % params.nSubsidyHalvingInterval, 0);
    BOOST_CHECK_GT(GetBlockSubsidy(end - 1, params), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(end, params), 0);
    BOOST_CHECK_EQUAL(end, 6930000);

    const auto& deployment{params.chainstate_revalidation_deployments.back()};
    BOOST_CHECK_EQUAL(deployment.name, "rolling_coinbase_maturity_1y");
    BOOST_CHECK_EQUAL(deployment.start_height, 995000);
    BOOST_CHECK_EQUAL(deployment.stop_height, std::numeric_limits<int>::max());

    // Other networks are unchanged.
    for (const auto& other : {CChainParams::TestNet4(), CChainParams::SigNet({}), CChainParams::RegTest({})}) {
        BOOST_CHECK_EQUAL(other->GetConsensus().CoinbaseMaturityRollingActivationHeight, std::numeric_limits<int>::max());
        BOOST_CHECK_EQUAL(other->GetConsensus().CoinbaseMaturityRolling, COINBASE_MATURITY);
    }
}

BOOST_FIXTURE_TEST_CASE(rolling_maturity_clean_activation, BasicTestingSetup)
{
    // Nothing a reward could do before activation is taken back: every covered reward mined
    // before activation is still locked by #468 in the last block before activation (and so in
    // every earlier block). This relies on RDTS expiring after activation, as it does on mainnet
    // (995000 is around February 2027; RDTS expires on September 1st, 2027).
    const auto main{CChainParams::Main()};
    const auto params{WithoutRolling(main->GetConsensus())};
    const int activation{main->GetConsensus().CoinbaseMaturityRollingActivationHeight};
    for (int coin = 979919; coin < activation; ++coin) {
        BOOST_REQUIRE(!SpendOk(params, coin, activation - 1));
    }

    // The bound is tight: the latest clean activation is 979919 + 25920. One block later,
    // the first covered reward could be spent first and locked again afterwards.
    BOOST_CHECK(!SpendOk(params, 979919, 979919 + 25920 - 1));
    BOOST_CHECK(SpendOk(params, 979919, 979919 + 25920));
}

BOOST_FIXTURE_TEST_CASE(rolling_maturity_one_reward_per_block, BasicTestingSetup)
{
    const auto main{CChainParams::Main()};
    const auto& params{main->GetConsensus()};
    for (int coin = 979919; coin < 979919 + 3000; ++coin) {
        BOOST_REQUIRE(!SpendOk(params, coin, coin + 52559));
        BOOST_REQUIRE(SpendOk(params, coin, coin + 52560));
    }
    // Rewards mined around activation and long after follow the same clock.
    for (const int coin : {994999, 995000, 1005839, 2000000}) {
        BOOST_CHECK(!SpendOk(params, coin, coin + 52559));
        BOOST_CHECK(SpendOk(params, coin, coin + 52560));
    }
    // Rewards before the start keep their earlier rules.
    BOOST_CHECK(SpendOk(params, 979918, 979918 + 100));
    BOOST_CHECK(SpendOk(params, 973439, 995000));
}

BOOST_FIXTURE_TEST_CASE(rolling_maturity_end_boundary, BasicTestingSetup)
{
    const auto main{CChainParams::Main()};
    const auto& params{main->GetConsensus()};
    // RDTS has long expired by then, so #468 no longer covers these rewards; the rolling rule does.
    const int expired{1000000};
    BOOST_CHECK(!SpendOk(params, 6929999, 6929999 + 52559, expired));
    BOOST_CHECK(SpendOk(params, 6929999, 6929999 + 52560, expired));
    BOOST_CHECK(!SpendOk(params, 6930000, 6930000 + 99, expired));
    BOOST_CHECK(SpendOk(params, 6930000, 6930000 + 100, expired));
}

BOOST_FIXTURE_TEST_CASE(rolling_maturity_combines_with_other_rules, BasicTestingSetup)
{
    // The rolling rule never shortens another rule: the larger requirement wins.
    Consensus::Params params;
    params.CoinbaseMaturityLongStartHeight = 100;
    params.CoinbaseMaturityLongEnforceHeight = 100;
    params.CoinbaseMaturityLongUntilRdts = true;
    params.CoinbaseMaturityLong = 300;
    params.CoinbaseMaturityRollingStartHeight = 100;
    params.CoinbaseMaturityRollingEndHeight = 1000;
    params.CoinbaseMaturityRollingActivationHeight = 200;
    params.CoinbaseMaturityRolling = 200;
    BOOST_CHECK(!SpendOk(params, 150, 150 + 299));
    BOOST_CHECK(SpendOk(params, 150, 150 + 300));
    params.CoinbaseMaturityRolling = 500;
    BOOST_CHECK(!SpendOk(params, 150, 150 + 499));
    BOOST_CHECK(SpendOk(params, 150, 150 + 500));
    // Before activation only the other rules apply.
    params.CoinbaseMaturityRollingActivationHeight = 1000;
    BOOST_CHECK(SpendOk(params, 150, 150 + 300));
}

BOOST_FIXTURE_TEST_CASE(rolling_maturity_independent_of_rdts, BasicTestingSetup)
{
    const auto main{CChainParams::Main()};
    for (const int64_t expiry : {std::numeric_limits<int64_t>::min(), int64_t{1296688603}, int64_t{1819756800}, std::numeric_limits<int64_t>::max()}) {
        auto params{main->GetConsensus()};
        params.RdtsExpiryTime = expiry;
        params.Blake2bHeight = 1;
        // #468 coverage ending anywhere (simulated by its end height) leaves the year intact.
        for (const int long_end : {979920, 990000, std::numeric_limits<int>::max()}) {
            for (const int coin : {979919, 990000, 1100000}) {
                BOOST_CHECK(!SpendOk(params, coin, coin + 52559, long_end));
                BOOST_CHECK(SpendOk(params, coin, coin + 52560, long_end));
            }
        }
        CBlockIndex parent;
        parent.nTime = expiry > 0 && expiry < std::numeric_limits<uint32_t>::max() ? expiry : 1;
        CBlockIndex reward;
        reward.pprev = &parent;
        reward.nHeight = 1100000;
        BOOST_CHECK_EQUAL(Consensus::CoinbaseMaturityPolicy(params, &reward), 52560);
    }
}

BOOST_FIXTURE_TEST_CASE(rolling_maturity_regtest_options, BasicTestingSetup)
{
    CChainParams::RegTestOptions options;
    options.coinbase_maturity_rolling_activation_height = 150;
    options.coinbase_maturity_rolling_start_height = 110;
    options.coinbase_maturity_rolling_end_height = 400;
    options.coinbase_maturity_rolling = 250;
    const auto regtest{CChainParams::RegTest(options)};
    const auto& params{regtest->GetConsensus()};
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityRolling, 250);
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityRollingRequired(109), COINBASE_MATURITY);
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityRollingRequired(110), 250);
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityRollingRequired(399), 250);
    BOOST_CHECK_EQUAL(params.CoinbaseMaturityRollingRequired(400), COINBASE_MATURITY);
    BOOST_REQUIRE_EQUAL(params.chainstate_revalidation_deployments.size(), 1);
    BOOST_CHECK_EQUAL(params.chainstate_revalidation_deployments[0].name, "rolling_coinbase_maturity_1y");
    BOOST_CHECK_EQUAL(params.chainstate_revalidation_deployments[0].start_height, 150);
}

BOOST_AUTO_TEST_SUITE_END()
