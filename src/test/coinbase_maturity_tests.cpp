// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/dynamic_cbm.h>
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
    BOOST_CHECK(!main_consensus.CoinbaseMaturityDynamic);
    BOOST_CHECK(!testnet4->GetConsensus().CoinbaseMaturityDynamic);
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
    BOOST_CHECK(!default_consensus.CoinbaseMaturityDynamic);
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


BOOST_AUTO_TEST_CASE(dynamic_cbm_target_ratio)
{
    using Consensus::CalculateDynamicCBMFromTargets;

    constexpr int initial = 25920;
    constexpr uint32_t normal = 0x1d00ffff;
    constexpr uint32_t harder = 0x1c7fff80;

    // Unchanged difficulty preserves maturity.
    BOOST_CHECK_EQUAL(
        CalculateDynamicCBMFromTargets(initial, normal, normal),
        initial);

    // Higher difficulty increases maturity.
    const int increased =
        CalculateDynamicCBMFromTargets(initial, normal, harder);
    BOOST_CHECK_GT(increased, initial);

    // Lower difficulty decreases maturity.
    const int decreased =
        CalculateDynamicCBMFromTargets(increased, harder, normal);
    BOOST_CHECK_LT(decreased, increased);

    // Maturity never falls below 100 blocks.
    BOOST_CHECK_GE(decreased, 100);

    // Halving difficulty must halve the initial maturity exactly.
    constexpr uint32_t easier = 0x1d01fffe;
    BOOST_CHECK_EQUAL(
        CalculateDynamicCBMFromTargets(initial, normal, easier),
        12960);
}

BOOST_AUTO_TEST_CASE(dynamic_cbm_arithmetic_limits)
{
    using Consensus::CalculateDynamicCBMFromTargets;
    // Near-256-bit targets exercise overflow-free fractional multiplication.
    BOOST_CHECK_EQUAL(CalculateDynamicCBMFromTargets(150, 0x2100fffe, 0x2100ffff), 149);
    BOOST_CHECK_EQUAL(CalculateDynamicCBMFromTargets(150, 0x2100ffff, 0x2100fffe), 150);
    BOOST_CHECK_EQUAL(CalculateDynamicCBMFromTargets(150, 0x207fffff, 0x207fffff), 150);
    BOOST_CHECK_EQUAL(CalculateDynamicCBMFromTargets(150, 0x203fffff, 0x207ffffe), 100);
    BOOST_CHECK_EQUAL(CalculateDynamicCBMFromTargets(150, 0x207fffff, 0x01010000),
                      Consensus::DYNAMIC_CBM_MAXIMUM);
    BOOST_CHECK_EQUAL(CalculateDynamicCBMFromTargets(150, 0, 0x1d00ffff), 0);
    BOOST_CHECK_EQUAL(CalculateDynamicCBMFromTargets(150, 0x1d00ffff, 0x1d80ffff), 0);
    BOOST_CHECK_EQUAL(CalculateDynamicCBMFromTargets(150, 0x23010000, 0x1d00ffff), 0);
    BOOST_CHECK_EQUAL(CalculateDynamicCBMFromTargets(1, 0x1d00ffff, 0x1d00ffff), 100);
}

BOOST_FIXTURE_TEST_CASE(dynamic_cbm_activation_boundary, BasicTestingSetup)
{
    Consensus::Params params;
    params.RdtsExpiryTime = 1000;
    params.CoinbaseMaturityDynamic = true;
    params.CoinbaseMaturityLong = 25920;
    params.CoinbaseMaturityLongUntilRdts = true;
    params.nPowTargetTimespan = 6000;
    params.nPowTargetSpacing = 600;

    std::vector<CBlockIndex> blocks(50);

    for (int i = 0; i < 50; ++i) {
        blocks[i].nHeight = i;
        blocks[i].nTime = 980 + i;
        blocks[i].nBits = 0x1d00ffff;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].BuildSkip();
    }

    // Block 25 reaches expiry MTP; block 26 activates DCBM.
    BOOST_CHECK_EQUAL(blocks[24].GetMedianTimePast(), 999);
    BOOST_CHECK_EQUAL(blocks[25].GetMedianTimePast(), 1000);

    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[25]),
        25920);

    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[26]),
        25920);

    // The first retarget after activation is height 30.
    // Unchanged difficulty must preserve maturity.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[30]),
        25920);
    // Increase difficulty at the first post-activation retarget.
    for (int i = 30; i < 40; ++i) {
        blocks[i].nBits = 0x1c7fff80;
    }

    const int64_t increased =
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[30]);

    BOOST_CHECK_EQUAL(increased, 51840);

    // The reward at block 29 keeps its original maturity.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[29]),
        25920);



    // Difficulty decreases at the next retarget.
    blocks[40].nBits = 0x1d00ffff;

    const int64_t decreased =
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[40]);

    BOOST_CHECK_EQUAL(decreased, 25920);

    // Earlier coinbase maturity remains unchanged.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[30]),
        increased);


    // Competing branch forks immediately before the retarget.
    std::vector<CBlockIndex> competing_branch(11);

    for (int i = 0; i < 11; ++i) {
        auto& block = competing_branch[i];
        block.nHeight = 30 + i;
        block.nTime = 1010 + i;
        block.nBits = 0x1d00ffff;
        block.pprev = i == 0
            ? &blocks[29]
            : &competing_branch[i - 1];
        block.BuildSkip();
    }

    // Same height, different branch, different maturity.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(
            params, &competing_branch[30 - 30]),
        25920);

    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[30]),
        51840);

    // Both branches retain their own maturity at height 40.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(
            params, &competing_branch[10]),
        25920);

    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[40]),
        25920);


    // Disabled DCBM regression checks.
    params.CoinbaseMaturityDynamic = false;

    // Before expiry, the existing long maturity remains in effect.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[25]),
        25920);

    // After expiry, RC5 returns to standard coinbase maturity.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[26]),
        100);

    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[30]),
        100);

    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[40]),
        100);

}


BOOST_FIXTURE_TEST_CASE(dynamic_cbm_transaction_maturity_boundary, BasicTestingSetup)
{
    Consensus::Params params;
    params.RdtsExpiryTime = 1000;
    params.CoinbaseMaturityDynamic = true;
    params.CoinbaseMaturityLongUntilRdts = true;
    params.CoinbaseMaturityLong = 25920;
    params.CoinbaseMaturityLongStartHeight = 20;
    params.CoinbaseMaturityLongEnforceHeight = 20;
    params.nPowTargetTimespan = 6000;
    params.nPowTargetSpacing = 600;

    constexpr int coin_height = 26;
    constexpr int maturity = 25920;
    constexpr int spend_height = coin_height + maturity;

    std::vector<CBlockIndex> blocks(spend_height + 1);

    for (int i = 0; i <= spend_height; ++i) {
        blocks[i].nHeight = i;
        blocks[i].nTime = 980 + i;
        blocks[i].nBits = 0x1d00ffff;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].BuildSkip();
    }

    BOOST_CHECK_EQUAL(blocks[25].GetMedianTimePast(), 1000);
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[coin_height]),
        maturity);

    CCoinsView base;
    CCoinsViewCache view{&base};

    const COutPoint outpoint{
        Txid::FromUint256(uint256::ONE), 0};

    view.AddCoin(outpoint, Coin{CTxOut{1000, CScript{}},
                               coin_height, true}, false);

    CMutableTransaction mutable_tx;
    mutable_tx.vin.emplace_back(outpoint);
    mutable_tx.vout.emplace_back(900, CScript{});

    const CTransaction tx{mutable_tx};

    auto check = [&](int height) {
        TxValidationState state;
        CAmount fee{0};

        return Consensus::CheckTxInputs(
            tx, state, view, height, fee,
            CheckTxInputsRules::None,
            params, blocks[height].pprev);
    };

    BOOST_CHECK(!check(spend_height - 1));
    BOOST_CHECK(check(spend_height));

    // A separately configured enforcement height must still be respected.
    params.CoinbaseMaturityLongEnforceHeight = coin_height + 101;
    BOOST_CHECK(check(coin_height + 100));
    BOOST_CHECK(!check(coin_height + 101));

    TxValidationState state;
    CAmount fee{0};
    BOOST_CHECK(!Consensus::CheckTxInputs(tx, state, view, spend_height, fee,
        CheckTxInputsRules::None, params, static_cast<const CBlockIndex*>(nullptr)));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-missing-dcbm-chain-context");

}


BOOST_FIXTURE_TEST_CASE(dynamic_cbm_decreasing_difficulty_spend, BasicTestingSetup)
{
    Consensus::Params params;
    params.RdtsExpiryTime = 1000;
    params.CoinbaseMaturityDynamic = true;
    params.CoinbaseMaturityLongUntilRdts = true;
    params.CoinbaseMaturityLong = 25920;
    params.CoinbaseMaturityLongStartHeight = 20;
    params.CoinbaseMaturityLongEnforceHeight = 20;
    params.nPowTargetTimespan = 6000;
    params.nPowTargetSpacing = 600;

    constexpr int coin_height = 30;
    constexpr int maturity = 12960;
    constexpr int spend_height = coin_height + maturity;

    std::vector<CBlockIndex> blocks(spend_height + 1);

    for (int i = 0; i <= spend_height; ++i) {
        auto& block = blocks[i];
        block.nHeight = i;
        block.nTime = 980 + i;
        block.nBits = i >= 30 ? 0x1d01fffe : 0x1d00ffff;
        block.pprev = i ? &blocks[i - 1] : nullptr;
        block.BuildSkip();
    }

    BOOST_REQUIRE_EQUAL(blocks[25].GetMedianTimePast(), 1000);

    BOOST_REQUIRE_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[coin_height]),
        maturity);

    CCoinsView base;
    CCoinsViewCache view{&base};

    const COutPoint outpoint{
        Txid::FromUint256(uint256::ONE), 0};

    view.AddCoin(outpoint,
                 Coin{CTxOut{1000, CScript{}}, coin_height, true},
                 false);

    CMutableTransaction mutable_tx;
    mutable_tx.vin.emplace_back(outpoint);
    mutable_tx.vout.emplace_back(900, CScript{});

    const CTransaction tx{mutable_tx};

    auto check = [&](int height) {
        TxValidationState state;
        CAmount fee{0};

        return Consensus::CheckTxInputs(
            tx, state, view, height, fee,
            CheckTxInputsRules::None,
            params, blocks[height].pprev);
    };

    BOOST_CHECK(!check(spend_height - 1));
    BOOST_CHECK(check(spend_height));
}


BOOST_FIXTURE_TEST_CASE(dynamic_cbm_pre_expiry_reward_protected, BasicTestingSetup)
{
    Consensus::Params params;
    params.RdtsExpiryTime = 1000;
    params.CoinbaseMaturityDynamic = true;
    params.CoinbaseMaturityLongUntilRdts = true;
    params.CoinbaseMaturityLong = 25920;
    params.CoinbaseMaturityLongStartHeight = 20;
    params.CoinbaseMaturityLongEnforceHeight = 20;
    params.nPowTargetTimespan = 6000;
    params.nPowTargetSpacing = 600;

    constexpr int coin_height = 25;
    constexpr int maturity = 25920;
    constexpr int spend_height = coin_height + maturity;

    std::vector<CBlockIndex> blocks(spend_height + 1);

    for (int i = 0; i <= spend_height; ++i) {
        auto& block = blocks[i];
        block.nHeight = i;
        block.nTime = 980 + i;
        block.nBits = i >= 30 ? 0x1d01fffe : 0x1d00ffff;
        block.pprev = i ? &blocks[i - 1] : nullptr;
        block.BuildSkip();
    }

    BOOST_REQUIRE_EQUAL(blocks[24].GetMedianTimePast(), 999);
    BOOST_REQUIRE_EQUAL(blocks[25].GetMedianTimePast(), 1000);

    BOOST_REQUIRE_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[coin_height]),
        maturity);

    BOOST_REQUIRE_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[30]),
        12960);

    CCoinsView base;
    CCoinsViewCache view{&base};

    const COutPoint outpoint{
        Txid::FromUint256(uint256::ONE), 0};

    view.AddCoin(outpoint,
                 Coin{CTxOut{1000, CScript{}}, coin_height, true},
                 false);

    CMutableTransaction mutable_tx;
    mutable_tx.vin.emplace_back(outpoint);
    mutable_tx.vout.emplace_back(900, CScript{});

    const CTransaction tx{mutable_tx};

    auto check = [&](int height) {
        TxValidationState state;
        CAmount fee{0};

        return Consensus::CheckTxInputs(
            tx, state, view, height, fee,
            CheckTxInputsRules::None,
            params, blocks[height].pprev);
    };

    // Later difficulty reductions must not shorten this reward's maturity.
    BOOST_CHECK(!check(coin_height + 12960));
    BOOST_CHECK(!check(spend_height - 1));
    BOOST_CHECK(check(spend_height));
}


BOOST_FIXTURE_TEST_CASE(dynamic_cbm_competing_branch_spend, BasicTestingSetup)
{
    Consensus::Params params;
    params.RdtsExpiryTime = 1000;
    params.CoinbaseMaturityDynamic = true;
    params.CoinbaseMaturityLongUntilRdts = true;
    params.CoinbaseMaturityLong = 25920;
    params.CoinbaseMaturityLongStartHeight = 20;
    params.CoinbaseMaturityLongEnforceHeight = 20;
    params.nPowTargetTimespan = 6000;
    params.nPowTargetSpacing = 600;

    constexpr int coin_height = 30;
    constexpr int spend_height = coin_height + 25920;

    std::vector<CBlockIndex> common(30);
    std::vector<CBlockIndex> main_branch(spend_height - 29);
    std::vector<CBlockIndex> competing_branch(spend_height - 29);

    for (int i = 0; i < 30; ++i) {
        auto& block = common[i];
        block.nHeight = i;
        block.nTime = 980 + i;
        block.nBits = 0x1d00ffff;
        block.pprev = i ? &common[i - 1] : nullptr;
        block.BuildSkip();
    }

    for (int height = 30; height <= spend_height; ++height) {
        const int index = height - 30;

        for (auto* branch : {&main_branch, &competing_branch}) {
            auto& block = (*branch)[index];
            block.nHeight = height;
            block.nTime = 980 + height;
            block.nBits = branch == &main_branch
                ? 0x1c7fff80 : 0x1d00ffff;
            block.pprev = index
                ? &(*branch)[index - 1] : &common[29];
            block.BuildSkip();
        }
    }

    BOOST_REQUIRE_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(
            params, &main_branch[0]), 51840);

    BOOST_REQUIRE_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(
            params, &competing_branch[0]), 25920);

    CCoinsView base;
    CCoinsViewCache view{&base};

    const COutPoint outpoint{
        Txid::FromUint256(uint256::ONE), 0};

    view.AddCoin(outpoint,
                 Coin{CTxOut{1000, CScript{}}, coin_height, true},
                 false);

    CMutableTransaction mutable_tx;
    mutable_tx.vin.emplace_back(outpoint);
    mutable_tx.vout.emplace_back(900, CScript{});

    const CTransaction tx{mutable_tx};

    auto check = [&](const CBlockIndex* spend_block) {
        TxValidationState state;
        CAmount fee{0};
        return Consensus::CheckTxInputs(
            tx, state, view, spend_height, fee,
            CheckTxInputsRules::None, params, spend_block->pprev);
    };

    BOOST_CHECK(!check(&main_branch.back()));
    BOOST_CHECK(check(&competing_branch.back()));
}


BOOST_FIXTURE_TEST_CASE(dynamic_cbm_expiry_at_retarget_boundary, BasicTestingSetup)
{
    Consensus::Params params;
    params.RdtsExpiryTime = 1004;
    params.CoinbaseMaturityDynamic = true;
    params.CoinbaseMaturityLong = 25920;
    params.CoinbaseMaturityLongUntilRdts = true;
    params.nPowTargetTimespan = 6000;
    params.nPowTargetSpacing = 600;

    std::vector<CBlockIndex> blocks(45);

    for (int i = 0; i < 45; ++i) {
        blocks[i].nHeight = i;
        blocks[i].nTime = 980 + i;
        blocks[i].nBits = i < 30 ? 0x1d00ffff : 0x1c7fff80;
        if (i >= 40) blocks[i].nBits = 0x1d00ffff;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].BuildSkip();
    }

    BOOST_REQUIRE_EQUAL(blocks[28].GetMedianTimePast(), 1003);
    BOOST_REQUIRE_EQUAL(blocks[29].GetMedianTimePast(), 1004);

    // DCBM begins at block 30, which is also a retarget.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[29]),
        25920);
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[30]),
        25920);
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[39]),
        25920);

    // The next retarget changes maturity.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[40]),
        12960);

    // Earlier coinbase retains its assigned maturity.
    BOOST_CHECK_EQUAL(
        Consensus::DynamicCBMMaturityForBlock(params, &blocks[30]),
        25920);
}


BOOST_FIXTURE_TEST_CASE(dynamic_cbm_preserves_historical_window, BasicTestingSetup)
{
    Consensus::Params params;
    params.CoinbaseMaturityDynamic = true;
    params.CoinbaseMaturityLongUntilRdts = true;
    params.CoinbaseMaturityHistoricalStartHeight = 100;
    params.CoinbaseMaturityHistoricalReleaseHeight = 200;
    params.CoinbaseMaturityLongStartHeight = 199;
    params.CoinbaseMaturityLongEnforceHeight = 199;
    params.CoinbaseMaturityLong = 25920;
    params.RdtsExpiryTime = 1000000;
    params.nPowTargetTimespan = 6000;
    params.nPowTargetSpacing = 600;

    std::vector<CBlockIndex> blocks(301);
    for (int i = 0; i < 301; ++i) {
        blocks[i].nHeight = i;
        blocks[i].nTime = 1000 + i;
        blocks[i].nBits = 0x1d00ffff;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].BuildSkip();
    }

    auto check = [&](int coin_height, int spend_height) {
        CCoinsView base;
        CCoinsViewCache view{&base};
        const COutPoint outpoint{
            Txid::FromUint256(uint256::ONE), 0};

        view.AddCoin(outpoint,
                     Coin{CTxOut{1000, CScript{}}, coin_height, true},
                     false);

        CMutableTransaction mutable_tx;
        mutable_tx.vin.emplace_back(outpoint);
        mutable_tx.vout.emplace_back(900, CScript{});

        TxValidationState state;
        CAmount fee{0};

        return Consensus::CheckTxInputs(
            CTransaction{mutable_tx}, state, view,
            spend_height, fee, CheckTxInputsRules::None,
            params, blocks[spend_height - 1].pprev
                ? &blocks[spend_height - 1]
                : nullptr);
    };

    // Historical restriction remains active through height 199.
    BOOST_CHECK(!check(100, 199));

    // Historical restriction ends at spending height 200.
    BOOST_CHECK(check(100, 200));

    // Rolling rewards cannot spend after only 100 blocks.
    BOOST_CHECK(!check(199, 299));
}

BOOST_FIXTURE_TEST_CASE(dynamic_cbm_activation_follows_branch, BasicTestingSetup)
{
    Consensus::Params params;
    params.CoinbaseMaturityDynamic = true;
    params.CoinbaseMaturityLong = 120;
    params.CoinbaseMaturityDynamicInitial = 150;
    params.RdtsExpiryTime = 1000;
    params.nPowTargetTimespan = 6000;
    params.nPowTargetSpacing = 600;
    std::vector<CBlockIndex> early(40), late(40);
    for (int i = 0; i < 40; ++i) {
        for (auto* branch : {&early, &late}) {
            auto& block = (*branch)[i];
            block.nHeight = i;
            block.nTime = (branch == &early ? 980 : 970) + i;
            block.nBits = 0x1d00ffff;
            block.pprev = i ? &(*branch)[i - 1] : nullptr;
            block.BuildSkip();
        }
    }
    BOOST_CHECK_EQUAL(Consensus::DynamicCBMMaturityForBlock(params, &early[25]), 120);
    BOOST_CHECK_EQUAL(Consensus::DynamicCBMMaturityForBlock(params, &early[26]), 150);
    BOOST_CHECK_EQUAL(Consensus::DynamicCBMMaturityForBlock(params, &late[26]), 120);
    BOOST_CHECK_EQUAL(Consensus::DynamicCBMMaturityForBlock(params, &late[35]), 120);
    BOOST_CHECK_EQUAL(Consensus::DynamicCBMMaturityForBlock(params, &late[36]), 150);
    // Revisiting a previously evaluated branch must not reuse the other branch's activation.
    BOOST_CHECK_EQUAL(Consensus::DynamicCBMMaturityForBlock(params, &early[26]), 150);
}

BOOST_AUTO_TEST_SUITE_END()
